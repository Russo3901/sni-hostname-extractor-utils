"""Parse a TLS ClientHello out of a captured TCP segment and pull the SNI.

The input is the *payload* of a TCP segment (i.e. the TLS record layer bytes),
not the IP or TCP headers.  Callers that have a raw packet must strip those
first; doing it here would require guessing at link-layer framing, which varies
between capture formats (pcap, pcapng, loopback, VLAN-tagged, ...).

Design decision: this module accepts exactly one ClientHello per call.  A TCP
segment can in principle carry a partial record or several records, but the
Server Name extension lives in the first ClientHello of the first handshake
record, so that is the only shape we promise to handle.  Anything else raises
:class:`SNIError` rather than returning ``None``, so that a caller cannot
silently mistake "parse failed" for "client sent no SNI".
"""

from __future__ import annotations

from typing import Optional

__all__ = ["extract_sni", "extract_sni_from_client_hello", "SNIError"]


class SNIError(ValueError):
    """Raised when the buffer is not a parseable ClientHello.

    Subclasses :class:`ValueError` so that callers who just want "bad input"
    handling can catch the builtin, while callers who care can catch this.
    """


# TLS record layer constants.
_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01

# Extension type for server_name (RFC 6066, section 3).
_EXTENSION_SERVER_NAME = 0x0000

# NameType for host_name (RFC 6066, section 3).
_NAME_TYPE_HOST_NAME = 0x00


def _read_u8(buf: bytes, offset: int) -> int:
    if offset + 1 > len(buf):
        raise SNIError("truncated: expected 1 byte at offset %d" % offset)
    return buf[offset]


def _read_u16(buf: bytes, offset: int) -> int:
    if offset + 2 > len(buf):
        raise SNIError("truncated: expected 2 bytes at offset %d" % offset)
    return (buf[offset] << 8) | buf[offset + 1]


def _read_u24(buf: bytes, offset: int) -> int:
    if offset + 3 > len(buf):
        raise SNIError("truncated: expected 3 bytes at offset %d" % offset)
    return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]


def extract_sni_from_client_hello(data: bytes) -> Optional[str]:
    """Return the SNI hostname from a TLS record containing a ClientHello.

    ``data`` must begin with the TLS record header (content type 0x16).  The
    return value is the ``host_name`` string from the server_name extension, or
    ``None`` if the ClientHello parsed cleanly but carried no SNI extension.

    :raises SNIError: if the bytes are not a well-formed single ClientHello.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SNIError("expected bytes-like input, got %s" % type(data).__name__)
    buf = bytes(data)

    # --- TLS record header -------------------------------------------------
    if len(buf) < 5:
        raise SNIError("truncated TLS record header")
    if buf[0] != _CONTENT_TYPE_HANDSHAKE:
        raise SNIError(
            "not a handshake record: content type 0x%02x" % buf[0]
        )
    # record version bytes 1..2 are deliberately not validated: TLS 1.3
    # ClientHellos still advertise 0x0301/0x0303 here and some stacks send
    # 0x0300.  Rejecting on version would break real captures.
    record_length = _read_u16(buf, 3)
    if record_length < 4:
        raise SNIError("record too short to contain a handshake header")
    if len(buf) < 5 + record_length:
        raise SNIError(
            "truncated record: header says %d bytes, have %d"
            % (record_length, len(buf) - 5)
        )
    # Ignore any trailing bytes after the record (e.g. a second record in the
    # same segment); we only promised to read the first one.
    record = buf[5:5 + record_length]

    # --- Handshake header --------------------------------------------------
    if len(record) < 4:
        raise SNIError("truncated handshake header")
    if record[0] != _HANDSHAKE_TYPE_CLIENT_HELLO:
        raise SNIError(
            "not a ClientHello: handshake type 0x%02x" % record[0]
        )
    body_length = _read_u24(record, 1)
    if len(record) < 4 + body_length:
        raise SNIError(
            "truncated ClientHello: header says %d bytes, have %d"
            % (body_length, len(record) - 4)
        )
    body = record[4:4 + body_length]

    # --- ClientHello body --------------------------------------------------
    # legacy_version (2) + random (32)
    if len(body) < 34:
        raise SNIError("truncated ClientHello body")
    pos = 34

    session_id_len = _read_u8(body, pos)
    pos += 1
    if pos + session_id_len > len(body):
        raise SNIError("session_id length runs past end of ClientHello")
    pos += session_id_len

    cipher_suites_len = _read_u16(body, pos)
    pos += 2
    if cipher_suites_len % 2 != 0:
        raise SNIError("cipher_suites length is not a multiple of 2")
    if pos + cipher_suites_len > len(body):
        raise SNIError("cipher_suites length runs past end of ClientHello")
    pos += cipher_suites_len

    compression_len = _read_u8(body, pos)
    pos += 1
    if pos + compression_len > len(body):
        raise SNIError("compression methods length runs past end of ClientHello")
    pos += compression_len

    # Extensions are optional in SSLv3-era ClientHellos.  If the buffer ends
    # here, there is simply no SNI.
    if pos == len(body):
        return None
    if pos + 2 > len(body):
        raise SNIError("truncated extensions length field")

    extensions_len = _read_u16(body, pos)
    pos += 2
    if pos + extensions_len > len(body):
        raise SNIError("extensions length runs past end of ClientHello")
    extensions_end = pos + extensions_len

    # --- Walk extensions looking for server_name ---------------------------
    while pos + 4 <= extensions_end:
        ext_type = _read_u16(body, pos)
        ext_len = _read_u16(body, pos + 2)
        pos += 4
        if pos + ext_len > extensions_end:
            raise SNIError(
                "extension 0x%04x length runs past end of extensions block"
                % ext_type
            )
        if ext_type == _EXTENSION_SERVER_NAME:
            return _parse_server_name(body[pos:pos + ext_len])
        pos += ext_len

    if pos != extensions_end:
        raise SNIError("trailing bytes inside extensions block")
    return None


def _parse_server_name(ext: bytes) -> Optional[str]:
    """Decode the body of a server_name extension.

    Returns ``None`` when the extension is present but contains no host_name
    entry (only other NameTypes, which RFC 6066 permits).
    """
    if len(ext) < 2:
        raise SNIError("server_name extension shorter than its length field")
    list_len = _read_u16(ext, 0)
    if list_len + 2 != len(ext):
        raise SNIError(
            "server_name list length %d does not match extension body %d"
            % (list_len, len(ext) - 2)
        )
    pos = 2
    end = len(ext)
    while pos + 3 <= end:
        name_type = _read_u8(ext, pos)
        name_len = _read_u16(ext, pos + 1)
        pos += 3
        if pos + name_len > end:
            raise SNIError("server_name entry length runs past extension body")
        if name_type == _NAME_TYPE_HOST_NAME:
            raw = ext[pos:pos + name_len]
            try:
                return raw.decode("ascii")
            except UnicodeDecodeError:
                # RFC 6066 says host_name is ASCII.  Anything else is a
                # malformed extension; surfacing it as an error beats
                # returning mojibake that will not match a certificate.
                raise SNIError("host_name is not ASCII") from None
        pos += name_len
    if pos != end:
        raise SNIError("trailing bytes inside server_name extension")
    return None


def extract_sni(data: bytes) -> Optional[str]:
    """Return the SNI hostname from a captured TCP segment payload.

    This is the convenience entry point: it is exactly
    :func:`extract_sni_from_client_hello` under a shorter name.  It exists
    because the common call site has no interest in the record-layer details.

    :raises SNIError: if the bytes are not a well-formed single ClientHello.
    """
    return extract_sni_from_client_hello(data)

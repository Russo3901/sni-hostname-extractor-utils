import unittest

from sni_hostname_extractor_utils import (
    SNIError,
    extract_sni,
    extract_sni_from_client_hello,
)


def _u16(value):
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _u24(value):
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def build_client_hello(
    hostname=None,
    extra_extensions=b"",
    session_id=b"",
    compression=b"\x00",
    cipher_suites=b"\x13\x01",
    include_extensions=True,
    record_version=b"\x03\x01",
):
    """Assemble a TLS record wrapping a ClientHello.

    Only the fields the parser actually reads are given real values; the
    random and legacy_version are fixed filler because nothing downstream
    depends on them.
    """
    body = b"\x03\x03" + b"\x00" * 32  # legacy_version + random
    body += bytes([len(session_id)]) + session_id
    body += _u16(len(cipher_suites)) + cipher_suites
    body += bytes([len(compression)]) + compression

    if include_extensions:
        exts = b""
        if hostname is not None:
            host = hostname.encode("ascii")
            entry = b"\x00" + _u16(len(host)) + host
            ext_body = _u16(len(entry)) + entry
            exts += _u16(0x0000) + _u16(len(ext_body)) + ext_body
        exts += extra_extensions
        body += _u16(len(exts)) + exts

    handshake = b"\x01" + _u24(len(body)) + body
    record = b"\x16" + record_version + _u16(len(handshake)) + handshake
    return record


class ExtractSniTests(unittest.TestCase):
    def test_extracts_simple_hostname(self):
        record = build_client_hello("example.org")
        self.assertEqual(extract_sni(record), "example.org")

    def test_extract_sni_from_client_hello_matches_short_name(self):
        record = build_client_hello("api.internal.test")
        self.assertEqual(
            extract_sni_from_client_hello(record), extract_sni(record)
        )

    def test_no_extensions_returns_none(self):
        # An SSLv3-era ClientHello with no extension block is still valid.
        record = build_client_hello(hostname=None, include_extensions=False)
        self.assertIsNone(extract_sni(record))

    def test_extensions_without_server_name_returns_none(self):
        # A supported_groups extension (type 10) with a tiny body.
        other = _u16(0x000a) + _u16(2) + b"\x00\x00"
        record = build_client_hello(hostname=None, extra_extensions=other)
        self.assertIsNone(extract_sni(record))

    def test_server_name_with_only_unknown_name_type_returns_none(self):
        # NameType 0x01 is not host_name; RFC 6066 allows other types.
        entry = b"\x01" + _u16(3) + b"abc"
        ext_body = _u16(len(entry)) + entry
        other = _u16(0x0000) + _u16(len(ext_body)) + ext_body
        record = build_client_hello(hostname=None, extra_extensions=other)
        self.assertIsNone(extract_sni(record))

    def test_server_name_found_after_other_extensions(self):
        other = _u16(0x000a) + _u16(2) + b"\x00\x02"
        record = build_client_hello("late.example", extra_extensions=other)
        self.assertEqual(extract_sni(record), "late.example")

    def test_nonzero_session_id_and_cipher_suites(self):
        record = build_client_hello(
            "session.example",
            session_id=b"\x01\x02\x03\x04",
            cipher_suites=b"\xc0\x2f\x13\x01",
        )
        self.assertEqual(extract_sni(record), "session.example")

    def test_trailing_bytes_after_record_are_ignored(self):
        # A single TCP segment can carry a second record; we promise only to
        # read the first ClientHello.
        record = build_client_hello("first.example") + b"\x14\x03\x03\x00\x01\x01"
        self.assertEqual(extract_sni(record), "first.example")

    def test_accepts_bytearray_and_memoryview(self):
        record = build_client_hello("bytes.example")
        self.assertEqual(extract_sni(bytearray(record)), "bytes.example")
        self.assertEqual(extract_sni(memoryview(record)), "bytes.example")

    # --- error paths -------------------------------------------------------

    def test_empty_input_raises(self):
        with self.assertRaises(SNIError):
            extract_sni(b"")

    def test_non_bytes_input_raises(self):
        with self.assertRaises(SNIError):
            extract_sni("not bytes")

    def test_non_handshake_content_type_raises(self):
        record = b"\x17\x03\x03\x00\x02\x00\x00"  # application_data
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_truncated_record_header_raises(self):
        with self.assertRaises(SNIError):
            extract_sni(b"\x16\x03\x01")

    def test_record_length_past_end_raises(self):
        record = build_client_hello("short.example")
        truncated = record[:6]
        with self.assertRaises(SNIError):
            extract_sni(truncated)

    def test_not_a_client_hello_raises(self):
        # Handshake type 0x02 is ServerHello.
        body = b"\x00" * 40
        handshake = b"\x02" + _u24(len(body)) + body
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_truncated_client_hello_body_raises(self):
        # Body shorter than legacy_version + random.
        handshake = b"\x01" + _u24(10) + b"\x03\x03" + b"\x00" * 8
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_session_id_length_past_end_raises(self):
        body = b"\x03\x03" + b"\x00" * 32 + b"\xff"  # claims 255 bytes
        handshake = b"\x01" + _u24(len(body)) + body
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_odd_cipher_suites_length_raises(self):
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00"  # empty session id
        body += _u16(3) + b"\x13\x01\x00"  # odd length
        body += b"\x01\x00"
        handshake = b"\x01" + _u24(len(body)) + body
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_extensions_length_past_end_raises(self):
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
        body += _u16(2) + b"\x13\x01" + b"\x01\x00"
        body += _u16(50) + b"\x00\x00"  # claims 50 bytes, provides 2
        handshake = b"\x01" + _u24(len(body)) + body
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_extension_length_past_end_raises(self):
        # A single extension whose declared length exceeds the block.
        ext = _u16(0x000a) + _u16(9) + b"\x00\x00"
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
        body += _u16(2) + b"\x13\x01" + b"\x01\x00"
        body += _u16(len(ext)) + ext
        handshake = b"\x01" + _u24(len(body)) + body
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_server_name_list_length_mismatch_raises(self):
        # server_name extension whose internal list length is wrong.
        host = b"a.example"
        entry = b"\x00" + _u16(len(host)) + host
        ext_body = _u16(len(entry) + 5) + entry  # 5 bytes too many
        ext = _u16(0x0000) + _u16(len(ext_body)) + ext_body
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
        body += _u16(2) + b"\x13\x01" + b"\x01\x00"
        body += _u16(len(ext)) + ext
        handshake = b"\x01" + _u24(len(body)) + body
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_non_ascii_hostname_raises(self):
        host = b"\xff\xfe"
        entry = b"\x00" + _u16(len(host)) + host
        ext_body = _u16(len(entry)) + entry
        ext = _u16(0x0000) + _u16(len(ext_body)) + ext_body
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
        body += _u16(2) + b"\x13\x01" + b"\x01\x00"
        body += _u16(len(ext)) + ext
        handshake = b"\x01" + _u24(len(body)) + body
        record = b"\x16\x03\x03" + _u16(len(handshake)) + handshake
        with self.assertRaises(SNIError):
            extract_sni(record)

    def test_sni_error_is_a_value_error(self):
        # Callers may reasonably catch the builtin; document that contract.
        self.assertTrue(issubclass(SNIError, ValueError))
        with self.assertRaises(ValueError):
            extract_sni(b"")


if __name__ == "__main__":
    unittest.main()

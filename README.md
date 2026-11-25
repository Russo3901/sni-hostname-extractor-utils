# sni-hostname-extractor-utils

Extract the Server Name Indication (SNI) hostname from the TLS ClientHello bytes
carried in a captured TCP segment.

```python
from sni_hostname_extractor_utils import extract_sni, SNIError

# `data` is the TCP segment payload: the TLS record layer, with the IP and
# TCP headers already stripped by whatever produced the capture.
data = bytes.fromhex(
    "16030100"  # record header: handshake, TLS 1.0, length filled below
)

try:
    hostname = extract_sni(data)
except SNIError as exc:
    print("not a ClientHello:", exc)
else:
    print(hostname)  # e.g. "api.internal.test", or None if the client sent no SNI
```

## Why this exists

When you have a packet capture and want to know which hostname a client asked
for, the answer is buried inside the ClientHello: a handshake record, a variable
length handshake body, a session id, a cipher suite list, a compression list,
and finally an extensions block that may or may not contain a `server_name`
extension. Writing that walk by hand is easy to get subtly wrong, and the failure
mode is nasty — a misread length silently returns a truncated hostname that no
longer matches the certificate.

This library does the walk and treats every malformed length as an error rather
than as a best-effort guess. The trade-off is that it refuses input a
more permissive parser might accept: a truncated record, an extension whose
declared length overruns the block, or a host_name that is not ASCII all raise
`SNIError`. If you are processing hostile or damaged captures, that is what you
want; if you want a "best effort" string out of anything, this is not it.

## API

- `extract_sni(data)` — parse `data` (bytes, bytearray, or memoryview) as a
  single TLS record containing a ClientHello and return the SNI hostname as a
  `str`, or `None` if the ClientHello parsed but carried no `server_name`
  extension. Raises `SNIError` on malformed input.
- `extract_sni_from_client_hello(data)` — identical behaviour under a longer
  name, for call sites where the record-layer context is worth spelling out.
- `SNIError` — subclass of `ValueError`, raised for all parse failures.

## What counts as one ClientHello

The input is expected to start at the TLS record header (content type `0x16`).
IP and TCP headers are not handled here, because link-layer framing varies
between capture formats and guessing at it produces wrong results more often
than it saves keystrokes. If the segment contains more than one TLS record, only
the first is read; a second record in the same segment is ignored. If the
ClientHello is split across two TCP segments, neither segment alone will parse —
reassemble first.

## The awkward edge

The `server_name` extension is allowed by RFC 6066 to contain name types other
than `host_name`. When the extension is present but holds no `host_name` entry,
this library returns `None`, the same as when the extension is absent entirely.
That is deliberate: the caller's question is "what hostname did the client ask
for", and "none" is the honest answer in both cases. If you need to distinguish
the two, inspect the raw bytes yourself.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.


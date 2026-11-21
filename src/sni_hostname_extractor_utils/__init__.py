"""Public surface for sni-hostname-extractor-utils.

Only the two names below are exported.  ``extract_sni`` is the common case;
``extract_sni_from_client_hello`` is available when the caller already knows
that the buffer starts at the TLS record and wants a distinct error signal.
"""

from .core import extract_sni, extract_sni_from_client_hello, SNIError

__all__ = ["extract_sni", "extract_sni_from_client_hello", "SNIError"]

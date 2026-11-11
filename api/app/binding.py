"""Certificate binding: RFC 8705 thumbprint of a client cert."""
import base64
import hashlib
import hmac


def thumbprint(der: bytes) -> str:
    """Return base64url (no padding) SHA-256 of the cert DER, the `x5t#S256` value."""
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")


def matches(cnf: str, der: bytes) -> bool:
    """True if `cnf` equals the cert thumbprint. Empty never matches."""
    if not cnf:
        return False
    # constant-time compare so response timing does not leak how many chars matched
    return hmac.compare_digest(cnf.encode(), thumbprint(der).encode())

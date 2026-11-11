"""Authorization check for protected endpoints."""
from . import binding


class AuthError(Exception):
    """A failed check: `reason` is the stable code, `status` the HTTP status (401 or 403)."""

    def __init__(self, reason: str, status: int = 401):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def authorize(peer_der: bytes | None, authorization: str | None, required_scope: str,
              pub, now: int) -> dict:
    """Run the full check order and return claims. Only insufficient_scope is 403."""
    from . import tokens  # tokens imports AuthError from here

    if not peer_der:
        raise AuthError("no_client_cert", 401)
    parts = (authorization or "").split(" ")
    # scheme is case-insensitive (RFC 7235)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise AuthError("malformed", 401)
    claims = tokens.verify(parts[1], pub, "api.demo", now)
    cnf = claims.get("cnf")
    thumb = cnf.get("x5t#S256") if isinstance(cnf, dict) else None
    if not isinstance(thumb, str) or not thumb:
        raise AuthError("no_cnf", 401)
    if not binding.matches(thumb, peer_der):
        raise AuthError("thumbprint_mismatch", 401)
    scope = claims.get("scope")
    if not isinstance(scope, str) or required_scope not in scope.split():
        raise AuthError("insufficient_scope", 403)
    return claims

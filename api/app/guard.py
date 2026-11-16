"""Authorization check for protected endpoints."""
from . import binding


class AuthError(Exception):
    """A failed check: `reason` is the stable code, `status` the HTTP status (401 or 403)."""

    def __init__(self, reason: str, status: int = 401):
        super().__init__(reason)
        self.reason = reason
        self.status = status


async def authorize(peer_der: bytes | None, authorization: str | None, required_scope: str,
                    resolve, now: int, dpop=None) -> dict:
    """Run the full check order and return claims. Only insufficient_scope is 403.

    `resolve` is the async kid -> public key lookup (the JWKS cache on the api).
    `dpop` is (proof headers, method, htu, JtiCache) on REST and None on gRPC, where the
    DPoP scheme is not accepted and a DPoP-bound token is refused as dpop_required."""
    from . import dpop as dp, tokens  # both import AuthError from here

    if not peer_der:
        raise AuthError("no_client_cert", 401)
    parts = (authorization or "").split(" ")
    # scheme is case-insensitive (RFC 7235)
    scheme = parts[0].lower()
    if len(parts) != 2 or not parts[1] or scheme not in ("bearer", "dpop") or (scheme == "dpop" and not dpop):
        raise AuthError("malformed", 401)
    claims = await tokens.verify(parts[1], resolve, "api.demo", now)
    cnf = claims.get("cnf")
    thumb = cnf.get("x5t#S256") if isinstance(cnf, dict) else None
    has_jkt = isinstance(cnf, dict) and "jkt" in cnf
    if scheme == "dpop":
        if not has_jkt:
            raise AuthError("bearer_required" if thumb else "no_cnf", 401)
        headers, method, htu, cache = dpop
        if not headers:
            raise AuthError(dp.MISSING, 401)
        if len(headers) > 1:
            raise AuthError(dp.MALFORMED, 401)
        proof_jkt = dp.verify_proof(headers[0], method=method, url=htu, now=now,
                                    access_token=parts[1], cache=cache)
        dp.bind_check(cnf, proof_jkt)  # bound by proof key, not by the client cert
    else:
        if has_jkt:
            raise AuthError("dpop_required", 401)
        if not isinstance(thumb, str) or not thumb:
            raise AuthError("no_cnf", 401)
        if not binding.matches(thumb, peer_der):
            raise AuthError("thumbprint_mismatch", 401)
    scope = claims.get("scope")
    if not isinstance(scope, str) or required_scope not in scope.split():
        raise AuthError("insufficient_scope", 403)
    return claims

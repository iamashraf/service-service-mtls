"""RFC 8693 token exchange: narrow a token for an audience. Pure logic, no HTTP."""
from . import binding, policy, tokens
from .guard import AuthError

GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


class ExchangeError(Exception):
    """An RFC 6749 error: `code` is the error, `desc` our stable reason."""

    def __init__(self, code: str, desc: str):
        super().__init__(code, desc)
        self.code, self.desc = code, desc


async def exchange(form: dict, der: bytes, cn: str, resolve, mint, now: int) -> dict:
    """Check order: request shape, subject token, thumbprint, audience, scope.

    `der`/`cn` are this connection's cert. `mint(sub, scopes, aud, cnf)` signs the new
    token. The new token never has more scope than the subject token and the policy."""
    subject, audience = form.get("subject_token"), form.get("audience")
    if not subject or not audience or form.get("subject_token_type") != ACCESS_TOKEN:
        raise ExchangeError("invalid_request", "missing_or_bad_parameter")
    try:
        claims = await tokens.verify(subject, resolve, "api.demo", now)
    except AuthError as e:
        raise ExchangeError("invalid_grant", e.reason)
    cnf = claims.get("cnf")
    thumb = cnf.get("x5t#S256") if isinstance(cnf, dict) else None
    if not isinstance(thumb, str) or not thumb:
        raise ExchangeError("invalid_grant", "no_cnf")
    if not binding.matches(thumb, der):
        raise ExchangeError("invalid_grant", "thumbprint_mismatch")
    if audience not in policy.audiences_for(cn):
        raise ExchangeError("invalid_target", "audience_not_allowed")
    have = claims.get("scope")
    have = have.split() if isinstance(have, str) else []
    want = form["scope"].split() if "scope" in form else have
    allowed = set(have) & set(policy.scopes_for(cn) or [])
    if not set(want) <= allowed:
        raise ExchangeError("invalid_scope", "scope_not_allowed")
    scopes = [s for s in have if s in want]  # subject order, no duplicates
    return {"access_token": mint(claims["sub"], scopes, audience, cnf),
            "issued_token_type": ACCESS_TOKEN, "token_type": "Bearer",
            "expires_in": tokens.TTL, "scope": " ".join(scopes)}

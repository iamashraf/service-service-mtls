"""Issue and verify ES256 certificate-bound JWTs."""
import os

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from . import binding
from .guard import AuthError

TTL = 300
ISS = os.environ.get("AUTH_ISS", "https://auth.demo:8443")


def issue(key: ec.EllipticCurvePrivateKey, sub: str, scopes: list[str], der: bytes | None,
          now: int, aud: str = "api.demo", iss: str = ISS, *, kid: str, cnf: dict | None = None) -> str:
    """Sign a token bound to the cert `der`, or carrying `cnf` as is (token exchange).
    Scopes must come from policy, never a request."""
    claims = {
        "iss": iss, "sub": sub, "aud": aud, "exp": now + TTL,
        "scope": " ".join(scopes),
        "cnf": cnf or {"x5t#S256": binding.thumbprint(der)},
    }
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": kid})


async def verify(token: str, resolve, aud: str, now: int, iss: str = ISS) -> dict:
    """Check alg and kid, then signature, expiry, audience, issuer. Raises AuthError.

    `resolve` is an async kid -> public key (None if unknown). The key comes from the
    kid in the header, but alg is pinned here, so the header cannot pick the algorithm."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AuthError("malformed", 401)
    # `none` and HS256 (keyed with the public key) are refused before anything else
    if header.get("alg") != "ES256":
        raise AuthError("bad_signature", 401)
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AuthError("malformed", 401)
    pub = await resolve(kid)
    if pub is None:  # same answer as a bad signature, so kid probing learns nothing
        raise AuthError("bad_signature", 401)
    try:
        # signature is verified here before any claim is looked at
        claims = jwt.decode(token, pub, algorithms=["ES256"],
                            options={"verify_exp": False, "verify_aud": False})
    except jwt.InvalidSignatureError:
        raise AuthError("bad_signature", 401)
    except jwt.PyJWTError:
        raise AuthError("malformed", 401)
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise AuthError("malformed", 401)
    if now > exp:
        raise AuthError("expired", 401)
    tok_aud = claims.get("aud")
    if tok_aud != aud and not (isinstance(tok_aud, list) and aud in tok_aud):
        raise AuthError("bad_audience", 401)
    if claims.get("iss") != iss:
        raise AuthError("bad_issuer", 401)
    return claims

"""Issue and verify ES256 certificate-bound JWTs."""
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from . import binding
from .guard import AuthError

TTL = 300


def issue(key: ec.EllipticCurvePrivateKey, sub: str, scopes: list[str], der: bytes,
          now: int, aud: str = "api.demo", iss: str = "https://api.demo") -> str:
    """Sign a token bound to the cert `der`. Scopes must come from policy, never a request."""
    claims = {
        "iss": iss, "sub": sub, "aud": aud, "exp": now + TTL,
        "scope": " ".join(scopes),
        "cnf": {"x5t#S256": binding.thumbprint(der)},
    }
    return jwt.encode(claims, key, algorithm="ES256")


def verify(token: str, pub, aud: str, now: int, iss: str = "https://api.demo") -> dict:
    """Check signature, then expiry, audience, then issuer. Raises AuthError; returns claims."""
    try:
        # alg pinned to ES256 so `none` and HS256 (keyed with the public key) are refused;
        # signature is verified here before any claim is looked at
        claims = jwt.decode(token, pub, algorithms=["ES256"],
                            options={"verify_exp": False, "verify_aud": False})
    except jwt.InvalidAlgorithmError:
        raise AuthError("bad_signature", 401)
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

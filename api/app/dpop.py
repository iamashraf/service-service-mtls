"""DPoP (RFC 9449) proof checks. Pure functions: no I/O, the clock is passed in as `now`."""
import base64
import hashlib
import hmac
import json
import uuid
from urllib.parse import urlsplit

import jwt
from jwt.algorithms import ECAlgorithm

from .guard import AuthError

# Reason codes. dpop_missing and dpop_jkt_mismatch are raised by the caller / bind_check.
MISSING = "dpop_missing"
MALFORMED = "dpop_malformed"
BAD_SIGNATURE = "dpop_bad_signature"
HTM = "dpop_htm"
HTU = "dpop_htu"
IAT = "dpop_iat"
ATH = "dpop_ath"
REPLAY = "dpop_replay"
JKT_MISMATCH = "dpop_jkt_mismatch"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def jkt(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC P-256 public JWK (required members only, sorted)."""
    members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    return _b64u(hashlib.sha256(json.dumps(members, sort_keys=True, separators=(",", ":")).encode()).digest())


class JtiCache:
    """Replay cache: jti -> expiry. In memory, single process: use a shared store with several replicas."""

    def __init__(self, ttl: int = 120, max_size: int = 10000):
        # a proof is accepted for iat +/- window, so keep a jti for 2 * window
        self.ttl = ttl
        self.max_size = max_size
        self._seen: dict[str, int] = {}

    def seen_before(self, jti: str, now: int) -> bool:
        """True if jti was already used. Otherwise record it and return False."""
        if len(self._seen) >= self.max_size:  # evict expired entries first
            self._seen = {k: v for k, v in self._seen.items() if v > now}
        if self._seen.get(jti, 0) > now:
            return True
        if len(self._seen) >= self.max_size:
            return True  # still full: fail closed rather than drop a live jti
        self._seen[jti] = now + self.ttl
        return False


def _htu_key(url: str) -> tuple[str, str, str]:
    u = urlsplit(url)  # query and fragment are ignored (RFC 9449 section 4.3)
    return u.scheme.lower(), u.netloc.lower(), u.path


def verify_proof(proof: str, *, method: str, url: str, now: int, access_token: str | None,
                 cache: JtiCache, window: int = 60) -> str:
    """Validate a DPoP proof and return the proof key thumbprint. Raises AuthError(reason, 401)."""
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError:
        raise AuthError(MALFORMED, 401)
    jwk = header.get("jwk")
    if (header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or not isinstance(jwk, dict)
            or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk
            or not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str)):
        raise AuthError(MALFORMED, 401)
    try:
        key = ECAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(proof, key, algorithms=["ES256"], options={
            "verify_exp": False, "verify_nbf": False, "verify_iat": False, "verify_aud": False})
    except jwt.InvalidSignatureError:
        raise AuthError(BAD_SIGNATURE, 401)
    except (jwt.PyJWTError, ValueError):
        raise AuthError(MALFORMED, 401)
    jti, iat = claims.get("jti"), claims.get("iat")
    if not isinstance(jti, str) or not jti:
        raise AuthError(MALFORMED, 401)
    if claims.get("htm") != method:  # exact match: methods are uppercase
        raise AuthError(HTM, 401)
    htu = claims.get("htu")
    if not isinstance(htu, str) or _htu_key(htu) != _htu_key(url):
        raise AuthError(HTU, 401)
    if type(iat) is not int or abs(now - iat) > window:
        raise AuthError(IAT, 401)
    if access_token is not None:
        ath = claims.get("ath")
        want = _b64u(hashlib.sha256(access_token.encode()).digest())
        if not isinstance(ath, str) or not hmac.compare_digest(ath.encode(), want.encode()):
            raise AuthError(ATH, 401)
    # last, so a proof that fails any other check never burns its jti
    if cache.seen_before(jti, now):
        raise AuthError(REPLAY, 401)
    return jkt(jwk)


def bind_check(cnf: dict | None, proof_jkt: str) -> None:
    """The token's cnf.jkt must equal the proof key thumbprint."""
    want = cnf.get("jkt") if isinstance(cnf, dict) else None
    if not isinstance(want, str) or not want or not hmac.compare_digest(want.encode(), proof_jkt.encode()):
        raise AuthError(JKT_MISMATCH, 401)


def make_proof(key, method: str, url: str, now: int, access_token: str | None = None,
               jti: str | None = None) -> str:
    """Build a proof signed with an EC P-256 private key (`key`). Used by tests and demo clients."""
    jwk = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    claims = {"jti": jti or str(uuid.uuid4()), "htm": method, "htu": url, "iat": now}
    if access_token is not None:
        claims["ath"] = _b64u(hashlib.sha256(access_token.encode()).digest())
    return jwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})

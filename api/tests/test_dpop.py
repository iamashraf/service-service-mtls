import base64
import hashlib
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from app import dpop
from app.guard import AuthError

NOW = 1_000_000
URL = "https://auth.demo:8443/token"
KEY = ec.generate_private_key(ec.SECP256R1())


def pub(key=KEY):
    return json.loads(ECAlgorithm.to_jwk(key.public_key()))


def proof(**kw):
    kw.setdefault("key", KEY)
    kw.setdefault("method", "POST")
    kw.setdefault("url", URL)
    kw.setdefault("now", NOW)
    return dpop.make_proof(**kw)


def check(p, **kw):
    kw.setdefault("method", "POST")
    kw.setdefault("url", URL)
    kw.setdefault("now", NOW)
    kw.setdefault("access_token", None)
    kw.setdefault("cache", dpop.JtiCache())
    return dpop.verify_proof(p, **kw)


def reason(p, **kw):
    with pytest.raises(AuthError) as e:
        check(p, **kw)
    assert e.value.status == 401
    return e.value.reason


def raw(claims=None, headers=None, key=KEY, alg="ES256"):
    c = {"jti": "j1", "htm": "POST", "htu": URL, "iat": NOW}
    c.update(claims or {})
    h = {"typ": "dpop+jwt", "jwk": pub()}
    h.update(headers or {})
    return jwt.encode(c, key, algorithm=alg, headers=h)


def test_valid_proof_returns_jkt():
    assert check(proof()) == dpop.jkt(pub())


def test_jkt_matches_independent_rfc7638():
    j = pub()
    canon = json.dumps({"crv": j["crv"], "kty": "EC", "x": j["x"], "y": j["y"]}, separators=(",", ":"))
    want = base64.urlsafe_b64encode(hashlib.sha256(canon.encode()).digest()).decode().rstrip("=")
    assert dpop.jkt(j) == want
    assert "=" not in dpop.jkt(j) and len(dpop.jkt(j)) == 43
    assert dpop.jkt({**j, "kid": "x", "use": "sig"}) == want  # extra members ignored


@pytest.mark.parametrize("p", ["garbage", "a.b.c", ""])
def test_not_a_jwt(p):
    assert reason(p) == dpop.MALFORMED


def test_bad_typ():
    assert reason(raw(headers={"typ": "JWT"})) == dpop.MALFORMED


def test_alg_none_rejected():
    h = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    tok = h({"typ": "dpop+jwt", "alg": "none", "jwk": pub()}) + "." + h(
        {"jti": "j", "htm": "POST", "htu": URL, "iat": NOW}) + "."
    assert reason(tok) == dpop.MALFORMED


def test_alg_hs256_rejected():
    tok = jwt.encode({"jti": "j", "htm": "POST", "htu": URL, "iat": NOW}, "k" * 32, algorithm="HS256",
                     headers={"typ": "dpop+jwt", "jwk": pub()})
    assert reason(tok) == dpop.MALFORMED


def test_missing_jwk_and_non_ec_jwk():
    assert reason(raw(headers={"jwk": None})) == dpop.MALFORMED
    assert reason(raw(headers={"jwk": {**pub(), "crv": "P-384"}})) == dpop.MALFORMED
    assert reason(raw(headers={"jwk": {**pub(), "kty": "RSA"}})) == dpop.MALFORMED


def test_jwk_with_private_member_rejected():
    priv = json.loads(ECAlgorithm.to_jwk(KEY))
    assert "d" in priv
    assert reason(raw(headers={"jwk": priv})) == dpop.MALFORMED


def test_signed_by_other_key_than_jwk():
    other = ec.generate_private_key(ec.SECP256R1())
    assert reason(raw(key=other)) == dpop.BAD_SIGNATURE


def test_missing_or_empty_jti():
    assert reason(raw({"jti": ""})) == dpop.MALFORMED
    assert reason(raw({"jti": 5})) == dpop.MALFORMED


def test_htm_exact():
    assert reason(proof(), method="GET") == dpop.HTM
    assert reason(proof(method="post")) == dpop.HTM  # lowercase proof vs uppercase request
    assert reason(proof(method="POST"), method="post") == dpop.HTM


def test_htu_mismatch_and_query_ignored():
    assert reason(proof(url="https://evil.demo/token")) == dpop.HTU
    assert reason(proof(url="http://auth.demo:8443/token")) == dpop.HTU
    assert reason(proof(url="https://auth.demo:8443/other")) == dpop.HTU
    assert reason(raw({"htu": 5})) == dpop.HTU
    assert check(proof(url=URL + "?a=1#frag")) == dpop.jkt(pub())
    assert check(proof(), url=URL + "?b=2") == dpop.jkt(pub())


@pytest.mark.parametrize("iat", [NOW - 61, NOW + 61, "x", NOW + 0.5])
def test_iat_out_of_window(iat):
    assert reason(raw({"iat": iat})) == dpop.IAT


def test_iat_window_edges_ok():
    check(raw({"iat": NOW - 60, "jti": "a"}))
    check(raw({"iat": NOW + 60, "jti": "b"}))


def test_ath():
    assert check(proof(access_token="tok"), access_token="tok")
    assert reason(proof(access_token="tok"), access_token="other") == dpop.ATH
    assert reason(proof(), access_token="tok") == dpop.ATH
    assert check(proof(access_token="tok"))  # not required when no token is checked


def test_replay_and_expiry_eviction():
    c = dpop.JtiCache(ttl=120, max_size=2)
    p = proof(jti="same")
    assert check(p, cache=c)
    assert reason(p, cache=c) == dpop.REPLAY
    # past the ttl the entry is gone; fresh iat so the proof is valid again
    later = NOW + 121
    assert check(proof(jti="same", now=later), cache=c, now=later)


def test_cache_evicts_expired_first_and_is_bounded():
    c = dpop.JtiCache(ttl=10, max_size=2)
    assert not c.seen_before("a", 0) and not c.seen_before("b", 0)
    assert c.seen_before("c", 5)  # full, nothing expired: fail closed
    assert not c.seen_before("c", 11)  # a and b expired, evicted
    assert len(c._seen) == 1


def test_failed_proof_does_not_record_jti():
    c = dpop.JtiCache()
    assert reason(proof(jti="j9"), method="GET", cache=c) == dpop.HTM
    assert reason(proof(jti="j9", access_token="t"), access_token="x", cache=c) == dpop.ATH
    assert check(proof(jti="j9"), cache=c)  # still usable


def test_bind_check():
    j = dpop.jkt(pub())
    dpop.bind_check({"jkt": j}, j)
    for cnf in (None, {}, {"jkt": 1}, {"jkt": ""}, {"jkt": "other"}, {"x5t#S256": j}, "str"):
        with pytest.raises(AuthError) as e:
            dpop.bind_check(cnf, j)
        assert (e.value.reason, e.value.status) == (dpop.JKT_MISMATCH, 401)


def test_constants():
    assert dpop.MISSING == "dpop_missing" and dpop.JKT_MISMATCH == "dpop_jkt_mismatch"

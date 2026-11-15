"""DPoP over real Hypercorn mTLS: auth issues jkt-bound tokens, the api checks the proofs."""
import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app import dpop, tls, tokens
from app.auth import create_app as create_auth_app
from app.exchange import ACCESS_TOKEN, GRANT
from app.jwks import JwksClient, mtls_fetcher
from app.keys import KeySet
from app.main import create_app as create_api_app
from test_app_tls import Server, client, pki, url  # noqa: F401  (pki is a fixture)


def start(pki, build, env):
    """A Server whose public URL env var names its own port."""
    s = Server(None, *pki["server"], pki["ca"])
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(env, f"https://localhost:{s.port}")
        s.app = build()
    return s


@pytest.fixture(scope="module")
def auth(pki):
    tls.install()
    keys = KeySet()
    with start(pki, lambda: create_auth_app(keys), "AUTH_PUBLIC_URL") as s:
        s.keys = keys
        yield s


@pytest.fixture(scope="module")
def srv(pki, auth):
    tls.install()
    fetch = mtls_fetcher(url(auth, "/.well-known/jwks.json"), *pki["api.demo"], pki["ca"])
    with start(pki, lambda: create_api_app(JwksClient(fetch).get), "API_PUBLIC_URL") as s:
        yield s


def newkey():
    return ec.generate_private_key(ec.SECP256R1())


def jkt_of(key):
    return dpop.jkt(json.loads(dpop.ECAlgorithm.to_jwk(key.public_key())))


def proof(s, key, method, path, tok=None, **kw):
    return dpop.make_proof(key, method, url(s, path), kw.pop("now", int(time.time())), tok, **kw)


def dpop_token(auth, pki, who="java-writer", key=None):
    """Token issued under a DPoP proof. Returns (response, key)."""
    key = key or newkey()
    with client(pki, who) as c:
        r = c.post(url(auth, "/token"), headers={"DPoP": proof(auth, key, "POST", "/token")})
    return r, key


def call(pki, srv, method, tok, p, who="java-writer", scheme="DPoP", **kw):
    h = {"Authorization": f"{scheme} {tok}"}
    if p is not None:
        h["DPoP"] = p
    with client(pki, who) as c:
        return c.request(method, url(srv, "/orders"), headers=h, **kw)


def fresh(auth, pki, who="java-writer"):
    r, key = dpop_token(auth, pki, who)
    return r.json()["access_token"], key


def reason(r, status=401):
    assert r.status_code == status, r.text
    return r.json()["error"]


def test_token_under_dpop_has_jkt_and_no_x5t(auth, pki):
    r, key = dpop_token(auth, pki)
    assert r.status_code == 200 and r.json()["token_type"] == "DPoP"
    pub = auth.keys.public(jwt.get_unverified_header(r.json()["access_token"])["kid"])
    claims = jwt.decode(r.json()["access_token"], pub, algorithms=["ES256"], audience="api.demo", issuer=tokens.ISS)
    assert claims["cnf"] == {"jkt": jkt_of(key)}


def test_valid_dpop_get_and_post(auth, srv, pki):
    tok, key = fresh(auth, pki)
    r = call(pki, srv, "POST", tok, proof(srv, key, "POST", "/orders", tok), json={"item": "d"})
    assert r.status_code == 201
    r = call(pki, srv, "GET", tok, proof(srv, key, "GET", "/orders", tok))
    assert r.status_code == 200 and "d" in r.json()["orders"]


def test_proof_from_other_key_is_jkt_mismatch(auth, srv, pki):
    tok, _ = fresh(auth, pki)
    r = call(pki, srv, "GET", tok, proof(srv, newkey(), "GET", "/orders", tok))
    assert reason(r) == "dpop_jkt_mismatch"


def test_wrong_htu_and_htm(auth, srv, pki):
    tok, key = fresh(auth, pki)
    assert reason(call(pki, srv, "GET", tok, proof(srv, key, "GET", "/other", tok))) == "dpop_htu"
    assert reason(call(pki, srv, "GET", tok, proof(srv, key, "POST", "/orders", tok))) == "dpop_htm"


def test_reused_jti_is_replay(auth, srv, pki):
    tok, key = fresh(auth, pki)
    p = proof(srv, key, "GET", "/orders", tok)
    assert call(pki, srv, "GET", tok, p).status_code == 200
    assert reason(call(pki, srv, "GET", tok, p)) == "dpop_replay"


def test_dpop_token_as_bearer_is_dpop_required(auth, srv, pki):
    tok, key = fresh(auth, pki)
    r = call(pki, srv, "GET", tok, proof(srv, key, "GET", "/orders", tok), scheme="Bearer")
    assert reason(r) == "dpop_required"


def test_cert_bound_token_with_dpop_scheme_is_bearer_required(auth, srv, pki):
    with client(pki, "java-writer") as c:
        tok = c.post(url(auth, "/token")).json()["access_token"]
    r = call(pki, srv, "GET", tok, proof(srv, newkey(), "GET", "/orders", tok))
    assert reason(r) == "bearer_required"


def test_missing_and_duplicate_dpop_header(auth, srv, pki):
    tok, key = fresh(auth, pki)
    assert reason(call(pki, srv, "GET", tok, None)) == "dpop_missing"
    p = lambda: proof(srv, key, "GET", "/orders", tok)
    with client(pki, "java-writer") as c:
        r = c.get(url(srv, "/orders"), headers=[("Authorization", f"DPoP {tok}"), ("DPoP", p()), ("DPoP", p())])
    assert reason(r) == "dpop_malformed"


def test_ath_for_another_token_is_ath_mismatch(auth, srv, pki):
    tok, key = fresh(auth, pki)
    other = tok + "x"
    assert reason(call(pki, srv, "GET", tok, proof(srv, key, "GET", "/orders", other))) == "dpop_ath"


def test_alg_none_and_hs256_proofs_rejected(auth, srv, pki):
    tok, key = fresh(auth, pki)
    jwk = json.loads(dpop.ECAlgorithm.to_jwk(key.public_key()))
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    claims = json.dumps({"jti": "j", "htm": "GET", "htu": url(srv, "/orders"), "iat": int(time.time())}).encode()
    for alg in ("none", "HS256"):
        p = b64(json.dumps({"alg": alg, "typ": "dpop+jwt", "jwk": jwk}).encode()) + "." + b64(claims) + "."
        assert reason(call(pki, srv, "GET", tok, p)) == "dpop_malformed"


def test_expired_iat(auth, srv, pki):
    tok, key = fresh(auth, pki)
    p = proof(srv, key, "GET", "/orders", tok, now=int(time.time()) - 3600)
    assert reason(call(pki, srv, "GET", tok, p)) == "dpop_iat"


def test_dpop_still_needs_scope_last(auth, srv, pki):
    tok, key = fresh(auth, pki, "java-reader")
    r = call(pki, srv, "POST", tok, proof(srv, key, "POST", "/orders", tok), who="java-reader", json={"item": "x"})
    assert reason(r, 403) == "insufficient_scope"


def test_token_endpoint_proof_failures_are_401(auth, pki):
    key = newkey()
    with client(pki, "java-writer") as c:
        r = c.post(url(auth, "/token"), headers={"DPoP": proof(auth, key, "GET", "/token")})
        assert reason(r) == "dpop_htm"
        p = proof(auth, key, "POST", "/token")
        assert c.post(url(auth, "/token"), headers={"DPoP": p}).status_code == 200
        assert reason(c.post(url(auth, "/token"), headers={"DPoP": p})) == "dpop_replay"


def test_exchange_of_dpop_subject_and_dpop_with_exchange(auth, pki):
    tok, key = fresh(auth, pki)
    form = {"grant_type": GRANT, "subject_token": tok, "subject_token_type": ACCESS_TOKEN, "audience": "api.demo"}
    with client(pki, "java-writer") as c:
        r = c.post(url(auth, "/token"), data=form)
        assert r.status_code == 400
        assert r.json() == {"error": "invalid_grant", "error_description": "dpop_subject_unsupported"}
        r = c.post(url(auth, "/token"), data=form, headers={"DPoP": proof(auth, key, "POST", "/token")})
        assert r.status_code == 400 and r.json()["error"] == "invalid_request"

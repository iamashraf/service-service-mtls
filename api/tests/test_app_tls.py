"""Live mTLS tests: real Hypercorn, real handshakes, certs generated in-test."""
import asyncio
import base64
import datetime
import json
import logging
import socket
import ssl
import threading
import time

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hypercorn.asyncio import serve

from app import binding, tls, tokens
from app.exchange import ACCESS_TOKEN, GRANT
from app.jwks import JwksClient, mtls_fetcher
from app.keys import KeySet

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn, issuer_key, issuer_cn, san=None, ca=False, key=None):
    """Make a P-256 cert for `cn` signed by `issuer_key` (self-signed CA if `ca`). Returns (key, cert)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    issuer_key = key if ca else issuer_key
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=1))
         .not_valid_after(now + datetime.timedelta(hours=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         # Python 3.13+ strict verification needs an AKI
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
             issuer_key.public_key()), critical=False))
    if ca:  # strict verification wants keyUsage on a CA
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return key, b.sign(issuer_key, hashes.SHA256())


def pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM)


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def write_pair(tmp, name, key, cert):
    """Write cert and key PEM files; return the two paths as strings."""
    cp, kp = tmp / f"{name}.crt", tmp / f"{name}.key"
    cp.write_bytes(pem_cert(cert))
    kp.write_bytes(pem_key(key))
    return str(cp), str(kp)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """Hypercorn running an ASGI app in a background thread."""

    def __init__(self, app, certfile, keyfile, ca_file):
        self.port = free_port()
        cfg = tls.Tls13Config()
        cfg.bind = [f"127.0.0.1:{self.port}"]
        cfg.certfile, cfg.keyfile, cfg.ca_certs = certfile, keyfile, ca_file
        cfg.verify_mode = ssl.CERT_REQUIRED
        self.app, self.cfg = app, cfg
        self.stop = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        loop = asyncio.new_event_loop()
        self.stop = asyncio.Event()
        loop.run_until_complete(serve(self.app, self.cfg, shutdown_trigger=self.stop.wait))

    def __enter__(self):
        self.thread.start()
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *a):
        self.stop._loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(5)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A demo CA, a server cert, writer/reader/stranger client certs, and a rogue CA client cert."""
    tmp = tmp_path_factory.mktemp("pki")
    ca_key, ca = make_cert("demo-ca", None, "demo-ca", ca=True)
    rogue_key, rogue = make_cert("rogue-ca", None, "rogue-ca", ca=True)
    out = {"ca": write_pair(tmp, "ca", ca_key, ca)[0],
           "server": write_pair(tmp, "server", *make_cert("localhost", ca_key, "demo-ca", san="localhost"))}
    for cn in ("java-writer", "java-reader", "stranger", "api.demo"):
        k, c = make_cert(cn, ca_key, "demo-ca")
        out[cn] = write_pair(tmp, cn, k, c)
        out[cn + ".der"] = c.public_bytes(serialization.Encoding.DER)
    k, c = make_cert("java-writer", rogue_key, "rogue-ca")
    out["rogue"] = write_pair(tmp, "rogue", k, c)
    return out


def client(pki, who):
    """httpx client trusting the demo CA, presenting `who`'s cert (None for no cert)."""
    ctx = ssl.create_default_context(cafile=pki["ca"])
    if who:
        ctx.load_cert_chain(*pki[who])
    return httpx.Client(verify=ctx, timeout=5)


def run_risk_app(pki, handler_sleep=0.0):
    """A bare ASGI app that answers with the thumbprint of the peer cert it sees."""
    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        await asyncio.sleep(handler_sleep)
        ident = tls.peer_identity()
        body = json.dumps({"cn": ident[1], "tp": binding.thumbprint(ident[0])} if ident else None).encode()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})
    return app


def test_risk_app_sees_the_peer_cert_the_client_presented(pki):
    """RISK CHECK: the app sees the DER of the cert the client sent."""
    tls.install()
    with Server(run_risk_app(pki), *pki["server"], pki["ca"]) as s, client(pki, "java-writer") as c:
        r = c.get(f"https://localhost:{s.port}/").json()
        r2 = c.get(f"https://localhost:{s.port}/").json()  # keep-alive, same connection
    assert r == {"cn": "java-writer", "tp": binding.thumbprint(pki["java-writer.der"])}
    assert r2 == r


def test_risk_concurrent_connections_do_not_leak_certs(pki):
    """RISK CHECK: parallel connections with different certs each see their own cert."""
    tls.install()
    from concurrent.futures import ThreadPoolExecutor

    def one(who):
        with client(pki, who) as c:
            return who, c.get(f"https://localhost:{s.port}/").json()

    with Server(run_risk_app(pki, 0.05), *pki["server"], pki["ca"]) as s:
        whos = ["java-writer", "java-reader", "stranger"] * 20
        with ThreadPoolExecutor(12) as ex:
            results = list(ex.map(one, whos))
    for who, r in results:
        assert r == {"cn": who, "tp": binding.thumbprint(pki[who + ".der"])}


# ---- app tests ----
from app.auth import create_app as create_auth_app  # noqa: E402
from app.main import create_app as create_api_app  # noqa: E402


def counted(app):
    """Wrap an ASGI app with a request counter."""
    counter = {"n": 0}

    async def counting(scope, receive, send):
        if scope["type"] == "http":
            counter["n"] += 1
        await app(scope, receive, send)
    return counting, counter


@pytest.fixture(scope="module")
def auth(pki):
    """The real auth app behind mTLS, with its KeySet and a request counter."""
    tls.install()
    keys = KeySet()
    app, counter = counted(create_auth_app(keys))
    with Server(app, *pki["server"], pki["ca"]) as s:
        s.keys, s.counter = keys, counter
        yield s


@pytest.fixture(scope="module")
def srv(pki, auth):
    """The real resource server behind mTLS. Its keys come from `auth` over mTLS (as api.demo)."""
    tls.install()
    fetch = mtls_fetcher(url(auth, "/.well-known/jwks.json"), *pki["api.demo"], pki["ca"])
    app, counter = counted(create_api_app(JwksClient(fetch).get))
    with Server(app, *pki["server"], pki["ca"]) as s:
        s.counter = counter
        yield s


def url(s, path):
    return f"https://localhost:{s.port}{path}"


def get_token(auth, pki, who, **kw):
    with client(pki, who) as c:
        return c.post(url(auth, "/token"), **kw)


def decode(auth, tok):
    pub = auth.keys.public(jwt.get_unverified_header(tok)["kid"])
    return jwt.decode(tok, pub, algorithms=["ES256"], audience="api.demo", issuer=tokens.ISS)


def test_token_for_writer_has_scopes_and_cnf(auth, pki):
    r = get_token(auth, pki, "java-writer")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 300
    assert body["scope"] == "orders:read orders:write"
    claims = decode(auth, body["access_token"])
    assert claims["sub"] == "java-writer"
    assert claims["scope"] == "orders:read orders:write"
    assert claims["cnf"]["x5t#S256"] == binding.thumbprint(pki["java-writer.der"])


def test_client_credentials_grant_is_the_initial_flow(auth, pki):
    r = get_token(auth, pki, "java-reader", data={"grant_type": "client_credentials"})
    assert r.status_code == 200 and r.json()["scope"] == "orders:read"


def test_unknown_grant_type_is_400(auth, pki):
    r = get_token(auth, pki, "java-reader", data={"grant_type": "password"})
    assert r.status_code == 400 and r.json() == {"error": "unsupported_grant_type"}


def test_unknown_cn_gets_403_no_policy(auth, pki):
    r = get_token(auth, pki, "stranger")
    assert r.status_code == 403 and r.json() == {"error": "no_policy"}


def bearer(auth, pki, who):
    return {"Authorization": "Bearer " + get_token(auth, pki, who).json()["access_token"]}


def test_orders_read_write_ok_for_writer(auth, srv, pki):
    h = bearer(auth, pki, "java-writer")
    with client(pki, "java-writer") as c:
        assert c.post(url(srv, "/orders"), json={"item": "book"}, headers=h).status_code == 201
        r = c.get(url(srv, "/orders"), headers=h)
    assert r.status_code == 200 and "book" in json.dumps(r.json())


def test_reader_post_is_403_insufficient_scope(auth, srv, pki):
    h = bearer(auth, pki, "java-reader")
    with client(pki, "java-reader") as c:
        r = c.post(url(srv, "/orders"), json={"item": "x"}, headers=h)
        assert r.status_code == 403 and r.json() == {"error": "insufficient_scope"}
        assert c.get(url(srv, "/orders"), headers=h).status_code == 200


def test_replayed_token_with_other_cert_is_401_thumbprint_mismatch(auth, srv, pki):
    h = bearer(auth, pki, "java-writer")
    with client(pki, "java-reader") as c:
        r = c.get(url(srv, "/orders"), headers=h)
    assert r.status_code == 401 and r.json() == {"error": "thumbprint_mismatch"}


def test_api_has_no_token_endpoint(srv, pki):
    with client(pki, "java-writer") as c:
        r = c.post(url(srv, "/token"))
    assert r.status_code == 404 and r.json() == {"error": "http_404"}


def forged(pki, auth, kid="evil"):
    """A token signed by a key that is not in the JWKS, with the writer's claims and cnf."""
    return tokens.issue(ec.generate_private_key(ec.SECP256R1()), "java-writer",
                        ["orders:read", "orders:write"], pki["java-writer.der"], int(time.time()),
                        kid=kid)


def test_token_signed_by_key_not_in_jwks_is_bad_signature(auth, srv, pki):
    with client(pki, "java-writer") as c:
        r = c.get(url(srv, "/orders"), headers={"Authorization": "Bearer " + forged(pki, auth)})
    assert r.status_code == 401 and r.json() == {"error": "bad_signature"}


def test_token_without_kid_is_malformed(auth, srv, pki):
    t = jwt.encode({"sub": "x"}, ec.generate_private_key(ec.SECP256R1()), algorithm="ES256")
    with client(pki, "java-writer") as c:
        r = c.get(url(srv, "/orders"), headers={"Authorization": "Bearer " + t})
    assert r.status_code == 401 and r.json() == {"error": "malformed"}


def test_alg_none_and_hs256_are_rejected_over_http(auth, srv, pki):
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    kid = auth.keys.current[0]
    claims = json.dumps({"iss": tokens.ISS, "aud": "api.demo", "exp": int(time.time()) + 99}).encode()
    for alg in ("none", "HS256"):
        t = b64(json.dumps({"alg": alg, "typ": "JWT", "kid": kid}).encode()) + "." + b64(claims) + "."
        with client(pki, "java-writer") as c:
            r = c.get(url(srv, "/orders"), headers={"Authorization": "Bearer " + t})
        assert r.status_code == 401 and r.json() == {"error": "bad_signature"}


def test_jwks_and_metadata_documents(auth, pki):
    with client(pki, "java-reader") as c:
        jwks = c.get(url(auth, "/.well-known/jwks.json")).json()
        meta = c.get(url(auth, "/.well-known/oauth-authorization-server")).json()
    assert [k["kid"] for k in jwks["keys"]] == [k["kid"] for k in auth.keys.jwks()["keys"]]
    assert meta["tls_client_certificate_bound_access_tokens"] is True
    assert meta["issuer"] == tokens.ISS and meta["jwks_uri"].endswith("/.well-known/jwks.json")
    assert meta["token_endpoint"] == tokens.ISS + "/token"
    assert set(meta["grant_types_supported"]) == {"client_credentials", GRANT}


def test_rogue_ca_client_cert_is_rejected_in_handshake(auth, pki):
    before = auth.counter["n"]
    with pytest.raises((httpx.TransportError, ssl.SSLError)) as e:
        get_token(auth, pki, "rogue")
    print("ROGUE EXC:", type(e.value).__name__, e.value)
    assert auth.counter["n"] == before  # no request reached the app


def test_scopes_ignore_request_body(auth, pki):
    r = get_token(auth, pki, "java-reader", json={"scope": "orders:write"},
                  params={"scope": "orders:write"}, headers={"X-Scope": "orders:write"})
    assert decode(auth, r.json()["access_token"])["scope"] == "orders:read"


def test_no_client_cert_is_rejected(auth, srv, pki):
    before = auth.counter["n"], srv.counter["n"]
    for s in (auth, srv):
        with pytest.raises((httpx.TransportError, ssl.SSLError)) as e:
            get_token(s, pki, None)
        print("NOCERT EXC:", type(e.value).__name__, e.value)
    assert (auth.counter["n"], srv.counter["n"]) == before


def test_tls12_client_is_rejected(auth, srv, pki):
    """A client capped at TLS 1.2 (with a valid cert) fails and no request reaches the app."""
    before = auth.counter["n"], srv.counter["n"]
    ctx = ssl.create_default_context(cafile=pki["ca"])
    ctx.load_cert_chain(*pki["java-writer"])
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    for s in (auth, srv):
        with pytest.raises((httpx.TransportError, ssl.SSLError)) as e:
            httpx.Client(verify=ctx, timeout=5).post(url(s, "/token"))
        print("TLS12 EXC:", type(e.value).__name__, e.value)
    assert (auth.counter["n"], srv.counter["n"]) == before


def test_bad_body_without_auth_is_401_not_422(srv, pki):
    with client(pki, "java-writer") as c:
        r = c.post(url(srv, "/orders"), json={"nope": 1})
    assert r.status_code == 401 and r.json() == {"error": "malformed"}


def test_bad_body_with_auth_is_422_invalid_body(auth, srv, pki):
    h = bearer(auth, pki, "java-writer")
    with client(pki, "java-writer") as c:
        r = c.post(url(srv, "/orders"), json={"nope": 1}, headers=h)
    assert r.status_code == 422 and r.json() == {"error": "invalid_body"}


def test_unknown_path_is_404_json(srv, pki):
    with client(pki, "java-writer") as c:
        r = c.get(url(srv, "/nope"))
    assert r.status_code == 404 and r.json() == {"error": "http_404"}


@pytest.mark.parametrize("body", [b"{bad", b"\xff\xfe\xfd"])
def test_malformed_body_without_auth_is_401(srv, pki, body):
    with client(pki, "java-writer") as c:
        r = c.post(url(srv, "/orders"), content=body, headers={"content-type": "application/json"})
    assert r.status_code == 401 and r.json() == {"error": "malformed"}


def test_one_log_line_per_request(auth, srv, pki, caplog):
    h = bearer(auth, pki, "java-writer")
    caplog.set_level(logging.INFO, logger="app")
    caplog.clear()
    with client(pki, "java-writer") as c:
        c.post(url(srv, "/orders"), json={"nope": 1}, headers=h)
        c.post(url(srv, "/orders"), json={"item": "ok"}, headers=h)
    lines = [r.getMessage() for r in caplog.records if r.name == "app" and "decision=" in r.getMessage()]
    assert [l.split("decision=")[1] for l in lines] == ["deny reason=invalid_body", "allow reason=ok"]


# ---- token exchange over HTTP ----
def exchange(auth, pki, who, subject, **over):
    form = {"grant_type": GRANT, "subject_token": subject, "subject_token_type": ACCESS_TOKEN,
            "audience": "api.demo", **over}
    return get_token(auth, pki, who, data=form)


def subject_of(auth, pki, who):
    return get_token(auth, pki, who).json()["access_token"]


def test_exchange_narrows_and_the_narrowed_token_works_at_the_api(auth, srv, pki):
    r = exchange(auth, pki, "java-writer", subject_of(auth, pki, "java-writer"), scope="orders:read")
    assert r.status_code == 200
    body = r.json()
    assert body["scope"] == "orders:read" and body["issued_token_type"] == ACCESS_TOKEN
    assert body["token_type"] == "Bearer" and body["expires_in"] == 300
    assert decode(auth, body["access_token"])["cnf"] == {"x5t#S256": binding.thumbprint(pki["java-writer.der"])}
    h = {"Authorization": "Bearer " + body["access_token"]}
    with client(pki, "java-writer") as c:
        assert c.get(url(srv, "/orders"), headers=h).status_code == 200
        r = c.post(url(srv, "/orders"), json={"item": "x"}, headers=h)
    assert r.status_code == 403 and r.json() == {"error": "insufficient_scope"}


def test_exchange_reader_asking_for_write_is_invalid_scope(auth, pki):
    r = exchange(auth, pki, "java-reader", subject_of(auth, pki, "java-reader"), scope="orders:write")
    assert r.status_code == 400 and r.json()["error"] == "invalid_scope"


def test_exchange_with_other_certs_subject_token_is_thumbprint_mismatch(auth, pki):
    r = exchange(auth, pki, "java-reader", subject_of(auth, pki, "java-writer"))
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_grant", "error_description": "thumbprint_mismatch"}


def test_exchange_unknown_audience_is_invalid_target(auth, pki):
    r = exchange(auth, pki, "java-writer", subject_of(auth, pki, "java-writer"), audience="other.demo")
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


def test_exchange_widened_scope_is_never_granted(auth, pki):
    sub = subject_of(auth, pki, "java-reader")
    for scope in ("orders:read orders:write", "orders:admin"):
        r = exchange(auth, pki, "java-reader", sub, scope=scope)
        assert r.status_code == 400 and r.json()["error"] == "invalid_scope"

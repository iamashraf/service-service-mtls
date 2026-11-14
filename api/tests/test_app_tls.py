"""Live mTLS tests: real Hypercorn, real handshakes, certs generated in-test."""
import asyncio
import datetime
import json
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

from app import binding, tls

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
    for cn in ("java-writer", "java-reader", "stranger"):
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
from app.main import create_app  # noqa: E402


@pytest.fixture(scope="module")
def srv(pki):
    """The real app behind mTLS, with a request counter and the signing key."""
    tls.install()
    key = ec.generate_private_key(ec.SECP256R1())
    app = create_app(key)
    counter = {"n": 0}

    async def counting(scope, receive, send):
        if scope["type"] == "http":
            counter["n"] += 1
        await app(scope, receive, send)

    with Server(counting, *pki["server"], pki["ca"]) as s:
        s.key, s.counter = key, counter
        yield s


def url(s, path):
    return f"https://localhost:{s.port}{path}"


def get_token(srv, pki, who, **kw):
    with client(pki, who) as c:
        return c.post(url(srv, "/token"), **kw)


def decode(srv, tok):
    return jwt.decode(tok, srv.key.public_key(), algorithms=["ES256"], audience="api.demo")


def test_token_for_writer_has_scopes_and_cnf(srv, pki):
    r = get_token(srv, pki, "java-writer")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 300
    claims = decode(srv, body["access_token"])
    assert claims["sub"] == "java-writer"
    assert claims["scope"] == "orders:read orders:write"
    assert claims["cnf"]["x5t#S256"] == binding.thumbprint(pki["java-writer.der"])


def test_unknown_cn_gets_403_no_policy(srv, pki):
    r = get_token(srv, pki, "stranger")
    assert r.status_code == 403 and r.json() == {"error": "no_policy"}


def bearer(srv, pki, who):
    return {"Authorization": "Bearer " + get_token(srv, pki, who).json()["access_token"]}


def test_orders_read_write_ok_for_writer(srv, pki):
    h = bearer(srv, pki, "java-writer")
    with client(pki, "java-writer") as c:
        assert c.post(url(srv, "/orders"), json={"item": "book"}, headers=h).status_code == 201
        r = c.get(url(srv, "/orders"), headers=h)
    assert r.status_code == 200 and "book" in json.dumps(r.json())


def test_reader_post_is_403_insufficient_scope(srv, pki):
    h = bearer(srv, pki, "java-reader")
    with client(pki, "java-reader") as c:
        r = c.post(url(srv, "/orders"), json={"item": "x"}, headers=h)
        assert r.status_code == 403 and r.json() == {"error": "insufficient_scope"}
        assert c.get(url(srv, "/orders"), headers=h).status_code == 200


def test_replayed_token_with_other_cert_is_401_thumbprint_mismatch(srv, pki):
    h = bearer(srv, pki, "java-writer")
    with client(pki, "java-reader") as c:
        r = c.get(url(srv, "/orders"), headers=h)
    assert r.status_code == 401 and r.json() == {"error": "thumbprint_mismatch"}


def test_rogue_ca_client_cert_is_rejected_in_handshake(srv, pki):
    before = srv.counter["n"]
    with pytest.raises((httpx.TransportError, ssl.SSLError)) as e:
        get_token(srv, pki, "rogue")
    print("ROGUE EXC:", type(e.value).__name__, e.value)
    assert srv.counter["n"] == before  # no request reached the app


def test_scopes_ignore_request_body(srv, pki):
    r = get_token(srv, pki, "java-reader", json={"scope": "orders:write"},
                  params={"scope": "orders:write"}, headers={"X-Scope": "orders:write"})
    assert decode(srv, r.json()["access_token"])["scope"] == "orders:read"


def test_no_client_cert_is_rejected(srv, pki):
    before = srv.counter["n"]
    with pytest.raises((httpx.TransportError, ssl.SSLError)) as e:
        get_token(srv, pki, None)
    print("NOCERT EXC:", type(e.value).__name__, e.value)
    assert srv.counter["n"] == before


def test_tls12_client_is_rejected(srv, pki):
    """A client capped at TLS 1.2 (with a valid cert) fails and no request reaches the app."""
    before = srv.counter["n"]
    ctx = ssl.create_default_context(cafile=pki["ca"])
    ctx.load_cert_chain(*pki["java-writer"])
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises((httpx.TransportError, ssl.SSLError)) as e:
        httpx.Client(verify=ctx, timeout=5).post(url(srv, "/token"))
    print("TLS12 EXC:", type(e.value).__name__, e.value)
    assert srv.counter["n"] == before


def test_bad_body_without_auth_is_401_not_422(srv, pki):
    with client(pki, "java-writer") as c:
        r = c.post(url(srv, "/orders"), json={"nope": 1})
    assert r.status_code == 401 and r.json() == {"error": "malformed"}


def test_bad_body_with_auth_is_422_invalid_body(srv, pki):
    h = bearer(srv, pki, "java-writer")
    with client(pki, "java-writer") as c:
        r = c.post(url(srv, "/orders"), json={"nope": 1}, headers=h)
    assert r.status_code == 422 and r.json() == {"error": "invalid_body"}


def test_unknown_path_is_404_json(srv, pki):
    with client(pki, "java-writer") as c:
        r = c.get(url(srv, "/nope"))
    assert r.status_code == 404 and r.json() == {"error": "http_404"}

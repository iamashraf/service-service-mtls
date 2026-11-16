"""Live gRPC tests: real grpc.aio server, real mTLS, certs generated in-test."""
import asyncio
import logging
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor

import grpc
import pytest

from app import binding, orders_pb2 as pb, orders_pb2_grpc
from app.grpc_server import create_server
from app.jwks import JwksClient, mtls_fetcher
from test_app_tls import auth, get_token, pki, url  # noqa: F401  (fixtures)


class GrpcServer:
    """The gRPC server in a background thread, like Server for Hypercorn."""

    def __init__(self, orders, resolve, pki):
        self.orders = orders
        paths = (pki["server"][0], pki["server"][1], pki["ca"])
        self.loop = asyncio.new_event_loop()
        self.server = self.port = None
        self.make = lambda: create_server(orders, resolve, paths, 0)
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        async def start():  # grpc.aio binds the server to the running loop, so build it there
            self.server, self.port = self.make()
            await self.server.start()
        asyncio.run_coroutine_threadsafe(start(), self.loop).result(5)
        return self

    def __exit__(self, *a):
        asyncio.run_coroutine_threadsafe(self.server.stop(0), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


@pytest.fixture(scope="module")
def gsrv(pki, auth):
    fetch = mtls_fetcher(url(auth, "/.well-known/jwks.json"), *pki["api.demo"], pki["ca"])
    with GrpcServer([], JwksClient(fetch).get, pki) as s:
        yield s


def channel(pki, who, port, ca=None):
    """Secure channel presenting `who`'s cert (None for no cert)."""
    read = lambda p: open(p, "rb").read()
    creds = grpc.ssl_channel_credentials(
        read(ca or pki["ca"]), read(pki[who][1]) if who else None, read(pki[who][0]) if who else None)
    return grpc.secure_channel(f"localhost:{port}", creds)


def token(auth, pki, who):
    return get_token(auth, pki, who).json()["access_token"]


def call(ch, method, tok, **kw):
    """Run List or Add; return ('OK', orders) or (status name, details)."""
    md = (("authorization", tok),) if tok is not None else ()
    stub = orders_pb2_grpc.OrdersStub(ch)
    try:
        req = pb.ListRequest() if method == "List" else pb.AddRequest(item=kw["item"])
        return "OK", list(getattr(stub, method)(req, metadata=md, timeout=5).orders)
    except grpc.RpcError as e:
        return e.code().name, e.details()


def test_writer_add_and_list(gsrv, auth, pki):
    tok = "Bearer " + token(auth, pki, "java-writer")
    with channel(pki, "java-writer", gsrv.port) as ch:
        assert call(ch, "Add", tok, item="widget") == ("OK", ["widget"])
        assert call(ch, "List", tok) == ("OK", ["widget"])
    assert gsrv.orders == ["widget"]  # the store is the shared list object


def test_reader_list_ok_add_denied(gsrv, auth, pki):
    tok = "Bearer " + token(auth, pki, "java-reader")
    with channel(pki, "java-reader", gsrv.port) as ch:
        assert call(ch, "List", tok)[0] == "OK"
        assert call(ch, "Add", tok, item="x") == ("PERMISSION_DENIED", "insufficient_scope")


def test_replay_with_other_cert_is_thumbprint_mismatch(gsrv, auth, pki):
    tok = "Bearer " + token(auth, pki, "java-writer")
    with channel(pki, "java-reader", gsrv.port) as ch:
        assert call(ch, "List", tok) == ("UNAUTHENTICATED", "thumbprint_mismatch")


@pytest.mark.parametrize("md,reason", [(None, "malformed"), ("Basic abc", "malformed"),
                                       ("Bearer", "malformed"), ("Bearer garbage", "malformed")])
def test_missing_or_malformed_authorization(gsrv, pki, md, reason):
    with channel(pki, "java-writer", gsrv.port) as ch:
        assert call(ch, "List", md) == ("UNAUTHENTICATED", reason)


def test_rogue_ca_cert_fails_at_handshake(gsrv, pki):
    with channel(pki, "rogue", gsrv.port) as ch:
        assert call(ch, "List", "Bearer x")[0] == "UNAVAILABLE"


def test_no_client_cert_fails_at_handshake(gsrv, pki):
    with channel(pki, None, gsrv.port) as ch:
        assert call(ch, "List", "Bearer x")[0] == "UNAVAILABLE"


def test_risk_concurrent_connections_do_not_leak_certs(gsrv, auth, pki):
    """RISK CHECK: parallel connections with different certs each see their own cert.

    A writer token on a reader channel must always be thumbprint_mismatch, and each
    channel's own token must always pass; one leaked cert would break either."""
    toks = {w: "Bearer " + token(auth, pki, w) for w in ("java-writer", "java-reader")}
    chans = {w: channel(pki, w, gsrv.port) for w in toks}

    def one(i):
        own, other = (("java-writer", "java-reader"), ("java-reader", "java-writer"))[i % 2]
        return (call(chans[own], "List", toks[own])[0], call(chans[own], "List", toks[other]))

    with ThreadPoolExecutor(12) as ex:
        results = list(ex.map(one, range(80)))
    assert set(results) == {("OK", ("UNAUTHENTICATED", "thumbprint_mismatch"))}
    for c in chans.values():
        c.close()


def test_one_log_line_per_call(gsrv, auth, pki, caplog):
    tok = "Bearer " + token(auth, pki, "java-reader")
    caplog.set_level(logging.INFO, logger="app")
    with channel(pki, "java-reader", gsrv.port) as ch:
        call(ch, "Add", tok, item="x")
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("grpc ")]
    assert lines == [f"grpc cn='java-reader' thumbprint={binding.thumbprint(pki['java-reader.der'])[:8]} "
                     "decision=deny reason=insufficient_scope"]


def test_tls13_channel_works_and_tls12_is_a_known_limit(gsrv, pki):
    """grpcio cannot force TLS 1.3 only (see grpc_server.py), so TLS 1.2 is still accepted.

    This pins the limit. If it starts failing, grpcio can enforce 1.3: set the
    floor, flip the 1.2 assertion, and drop the known limit from the docs."""
    def handshake(max_version):
        ctx = ssl.create_default_context(cafile=pki["ca"])
        ctx.load_cert_chain(*pki["java-writer"])
        ctx.maximum_version = max_version
        ctx.set_alpn_protocols(["h2"])
        with socket.create_connection(("127.0.0.1", gsrv.port), 3) as s, \
                ctx.wrap_socket(s, server_hostname="localhost") as t:
            return t.version()
    assert handshake(ssl.TLSVersion.TLSv1_3) == "TLSv1.3"
    assert handshake(ssl.TLSVersion.TLSv1_2) == "TLSv1.2"


def test_proto_copies_match():
    """The Java client keeps its own copy of the proto; the two must stay identical."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    a, b = root / "api/proto/orders.proto", root / "client/src/main/proto/orders.proto"
    if not b.exists():
        pytest.skip("client proto not present yet")
    assert a.read_bytes() == b.read_bytes()

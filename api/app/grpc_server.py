"""gRPC Orders service: the same mTLS binding and scope checks as REST, via guard.authorize.

TLS 1.3 only is NOT enforced here. grpcio has no minimum-version option and
GRPC_SSL_CIPHER_SUITES only sets TLS 1.2 ciphers (a TLS 1.3 suite name is rejected as an
invalid cipher list), so a TLS 1.2 client still connects. test_grpc.py pins that limit.
The client cert is still required and verified against the demo CA.
"""
import logging
import ssl
import time

import grpc

from . import binding, orders_pb2 as pb, orders_pb2_grpc, tls
from .guard import AuthError, authorize

log = logging.getLogger("app")
# REST status -> gRPC status; insufficient_scope is the only 403
CODES = {401: grpc.StatusCode.UNAUTHENTICATED, 403: grpc.StatusCode.PERMISSION_DENIED}


class Orders(orders_pb2_grpc.OrdersServicer):
    """List needs orders:read, Add needs orders:write. `orders` is shared with REST."""

    def __init__(self, orders: list[str], resolve, now=time.time):
        self.orders, self.resolve, self.now = orders, resolve, now

    async def _check(self, context, scope: str):
        """Authorize this call or abort it. Returns the peer identity (DER, CN) for logging."""
        pems = context.auth_context().get("x509_pem_cert")
        # this connection's own cert: gRPC keeps the auth context per connection, not per process
        ident = tls.identity(ssl.PEM_cert_to_DER_cert(pems[0].decode())) if pems else None
        auths = [v for k, v in context.invocation_metadata() if k == "authorization"]
        try:
            await authorize(ident[0] if ident else None, auths[0] if len(auths) == 1 else None,
                            scope, self.resolve, int(self.now()))
        except AuthError as e:
            self._log(ident, "deny", e.reason)
            await context.abort(CODES[e.status], e.reason)
        return ident

    @staticmethod
    def _log(ident, decision: str, reason: str) -> None:
        """One line per call, same fields as the REST log."""
        cn = ident[1] if ident else None
        tp = binding.thumbprint(ident[0])[:8] if ident else "-"
        log.info("grpc cn=%r thumbprint=%s decision=%s reason=%s", cn, tp, decision, reason)

    async def List(self, request, context):
        ident = await self._check(context, "orders:read")
        self._log(ident, "allow", "ok")
        return pb.ListReply(orders=self.orders)

    async def Add(self, request, context):
        ident = await self._check(context, "orders:write")
        self.orders.append(request.item)
        self._log(ident, "allow", "ok")
        return pb.ListReply(orders=self.orders)


def create_server(orders: list[str], resolve, paths: tuple[str, str, str], port: int,
                  now=time.time) -> tuple[grpc.aio.Server, int]:
    """Build (not start) the server. `paths` is (cert, key, ca). Returns (server, bound port)."""
    cert, key, ca = (open(p, "rb").read() for p in paths)
    server = grpc.aio.server()
    orders_pb2_grpc.add_OrdersServicer_to_server(Orders(orders, resolve, now), server)
    # require_client_auth: the handshake rejects clients without a cert from the demo CA
    creds = grpc.ssl_server_credentials([(key, cert)], root_certificates=ca, require_client_auth=True)
    return server, server.add_secure_port(f"0.0.0.0:{port}", creds)

"""Peer certificate identity for the ASGI app.

Hypercorn verifies client certs but does not put them in the ASGI scope, so a small
TCPServer subclass copies the peer DER into a ContextVar once per connection.
"""
import contextvars
import ssl

from cryptography import x509
from cryptography.x509.oid import NameOID
from hypercorn.asyncio import run as hc_run
from hypercorn.config import Config
from hypercorn.asyncio.tcp_server import TCPServer

_peer_der: contextvars.ContextVar[bytes | None] = contextvars.ContextVar("peer_der", default=None)


class PeerCertTCPServer(TCPServer):
    """Hypercorn connection handler that records the TLS peer cert for this connection."""

    async def run(self) -> None:
        """Set the peer DER, then run the normal handler.

        asyncio only calls the connection callback after the TLS handshake (and, under
        CERT_REQUIRED, client cert verification) has finished. The ASGI tasks are created
        inside this same task, so they inherit the ContextVar. Depends on Hypercorn internals,
        so the version is pinned.
        """
        ssl_object = self.writer.get_extra_info("ssl_object")
        _peer_der.set(ssl_object.getpeercert(binary_form=True) if ssl_object else None)
        await super().run()


class Tls13Config(Config):
    """Hypercorn Config that refuses TLS older than 1.3 (Hypercorn hard-codes a 1.2 floor)."""

    def create_ssl_context(self) -> ssl.SSLContext:
        """Build the normal context, then raise the minimum version to TLS 1.3."""
        ctx = super().create_ssl_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        return ctx


def install() -> None:
    """Make Hypercorn use PeerCertTCPServer. Call once before serving."""
    hc_run.TCPServer = PeerCertTCPServer


def peer_identity() -> tuple[bytes, str] | None:
    """Return (leaf DER, CN) of this connection's client cert, or None if there is none.

    The CN is trusted only because the server runs with CERT_REQUIRED: the handshake
    already verified the chain against the demo CA before this value was set.
    """
    der = _peer_der.get()
    if not der:
        return None
    try:
        cns = x509.load_der_x509_certificate(der).subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    except ValueError:
        return der, ""
    # no CN, or an ambiguous one, gets "" so policy lookup fails with no_policy
    return der, cns[0].value if len(cns) == 1 else ""

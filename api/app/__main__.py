"""Entry point: enroll with the CA, then serve mTLS on :8443."""
import asyncio
import logging
import os
import ssl
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from hypercorn.asyncio import serve
from hypercorn.config import Config

from . import enroll, tls
from .main import create_app


def main() -> None:
    """Enroll as api.demo, write the cert files, and run Hypercorn with client certs required."""
    logging.basicConfig(level=logging.INFO)
    dns = ["api.demo"] + (["localhost"] if os.environ.get("DEMO_LOCAL") == "1" else [])
    bundle = enroll.fetch(os.environ.get("CA_URL", "http://ca.demo:8080"), "api.demo", "server", dns)
    tmp = Path(tempfile.mkdtemp())
    for name, key in (("cert.pem", "cert_pem"), ("key.pem", "key_pem"), ("ca.pem", "ca_pem")):
        p = tmp / name
        p.touch(mode=0o600)  # the private key must not be world-readable
        p.write_text(bundle[key])
    cfg = Config()
    cfg.bind = ["0.0.0.0:8443"]
    cfg.certfile, cfg.keyfile, cfg.ca_certs = str(tmp / "cert.pem"), str(tmp / "key.pem"), str(tmp / "ca.pem")
    # CERT_REQUIRED: the handshake rejects clients without a cert from the demo CA
    cfg.verify_mode = ssl.CERT_REQUIRED
    cfg.ssl_minimum_version = ssl.TLSVersion.TLSv1_3
    tls.install()
    # signing key lives only in memory; a restart invalidates old tokens
    app = create_app(ec.generate_private_key(ec.SECP256R1()))
    asyncio.run(serve(app, cfg))


if __name__ == "__main__":
    main()

"""Shared startup for auth and api: enroll as kind "both", then serve mTLS on :8443."""
import logging
import os
import ssl
import tempfile
from pathlib import Path

from hypercorn.asyncio import serve

from . import enroll, tls


def bootstrap(name: str) -> tuple[str, str, str]:
    """Enroll `name` (ENROLL_SECRET) and write cert, key and CA files. Returns the three paths."""
    logging.basicConfig(level=logging.INFO)
    dns = [name] + (["localhost"] if os.environ.get("DEMO_LOCAL") == "1" else [])
    # kind "both": the cert is used as a TLS server and, for the api, as a client of auth
    bundle = enroll.fetch(os.environ.get("CA_URL", "http://ca.demo:8080"), name, "both", dns)
    tmp = Path(tempfile.mkdtemp())
    paths = []
    for fname, key in (("cert.pem", "cert_pem"), ("key.pem", "key_pem"), ("ca.pem", "ca_pem")):
        p = tmp / fname
        p.touch(mode=0o600)  # the private key must not be world-readable
        p.write_text(bundle[key])
        paths.append(str(p))
    return tuple(paths)


async def serve_mtls(app, paths: tuple[str, str, str]) -> None:
    """Run Hypercorn on :8443 with TLS 1.3 and client certs required."""
    cfg = tls.Tls13Config()
    cfg.bind = ["0.0.0.0:8443"]
    cfg.certfile, cfg.keyfile, cfg.ca_certs = paths
    # CERT_REQUIRED: the handshake rejects clients without a cert from the demo CA
    cfg.verify_mode = ssl.CERT_REQUIRED
    tls.install()
    await serve(app, cfg)

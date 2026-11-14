"""Enroll with the mock CA: the key is generated here and only a CSR is sent."""
import os
import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def fetch(ca_url: str, name: str, kind: str, dns: list[str]) -> dict:
    """POST /enroll with a CSR and return {"cert_pem","key_pem","ca_pem"}.

    The private key is made here and never sent. The CA decides name and SANs, so the
    CSR subject is only a label. The secret comes from ENROLL_SECRET.
    Retries connection errors only (20 x 250ms) while the CA starts; 4xx/5xx raise at once.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
           .sign(key, hashes.SHA256()))
    body = {"name": name, "kind": kind, "dns": dns,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}
    headers = {"X-Enroll-Secret": os.environ.get("ENROLL_SECRET", "")}
    for attempt in range(20):
        try:
            r = httpx.post(f"{ca_url}/enroll", json=body, headers=headers, timeout=5)
            break
        except httpx.ConnectError:
            if attempt == 19:
                raise
            time.sleep(0.25)
    r.raise_for_status()
    out = r.json()
    out["key_pem"] = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    return out

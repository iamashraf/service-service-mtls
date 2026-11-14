import secrets

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import enroll


class _Resp:
    def raise_for_status(self):
        pass

    def json(self):
        return {"cert_pem": "c", "ca_pem": "ca"}


def test_fetch_sends_csr_and_secret_never_the_key(monkeypatch):
    sent = {}
    secret = secrets.token_hex(16)

    def post(url, json, headers, timeout):
        sent.update(url=url, json=json, headers=headers)
        return _Resp()

    monkeypatch.setattr(enroll.httpx, "post", post)
    monkeypatch.setenv("ENROLL_SECRET", secret)
    out = enroll.fetch("http://ca", "api.demo", "server", ["api.demo"])

    assert sent["headers"] == {"X-Enroll-Secret": secret}
    assert "key_pem" not in sent["json"] and "PRIVATE" not in str(sent["json"])
    csr = x509.load_pem_x509_csr(sent["json"]["csr_pem"].encode())
    assert csr.is_signature_valid
    key = serialization.load_pem_private_key(out["key_pem"].encode(), None)
    assert csr.public_key().public_numbers() == key.public_key().public_numbers()

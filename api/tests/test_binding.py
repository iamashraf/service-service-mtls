import base64
import hashlib

from app import binding

DER = b"\x30\x82\x01\x0apretend-certificate-der"


def test_thumbprint_known_vector():
    want = base64.urlsafe_b64encode(hashlib.sha256(DER).digest()).decode().rstrip("=")
    got = binding.thumbprint(DER)
    assert got == want
    assert len(got) == 43 and "=" not in got


def test_matches():
    tp = binding.thumbprint(DER)
    assert binding.matches(tp, DER)
    assert not binding.matches(tp, DER + b"x")
    assert not binding.matches("", DER)

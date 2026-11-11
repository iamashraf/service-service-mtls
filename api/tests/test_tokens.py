import base64
import hashlib
import hmac
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import binding, tokens
from app.guard import AuthError

NOW = 1_000_000
DER = b"cert-der"


@pytest.fixture(scope="module")
def key():
    return ec.generate_private_key(ec.SECP256R1())


def reason(token, pub, aud="api.demo", now=NOW):
    with pytest.raises(AuthError) as e:
        tokens.verify(token, pub, aud, now)
    return e.value.reason


def test_round_trip(key):
    t = tokens.issue(key, "java-writer", ["orders:read"], DER, NOW)
    c = tokens.verify(t, key.public_key(), "api.demo", NOW)
    assert c["sub"] == "java-writer" and c["scope"] == "orders:read"
    assert c["aud"] == "api.demo" and c["iss"] == "https://api.demo"
    assert c["exp"] == NOW + 300
    assert c["cnf"] == {"x5t#S256": binding.thumbprint(DER)}


def test_tampered_payload(key):
    h, p, s = tokens.issue(key, "a", ["orders:read"], DER, NOW).split(".")
    body = json.loads(base64.urlsafe_b64decode(p + "=="))
    body["scope"] = "orders:write"
    p2 = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")
    assert reason(f"{h}.{p2}.{s}", key.public_key()) == "bad_signature"


def test_wrong_key(key):
    other = ec.generate_private_key(ec.SECP256R1())
    t = tokens.issue(other, "a", [], DER, NOW)
    assert reason(t, key.public_key()) == "bad_signature"


def test_expired(key):
    t = tokens.issue(key, "a", [], DER, NOW)
    assert reason(t, key.public_key(), now=NOW + 301) == "expired"


def test_wrong_audience(key):
    t = tokens.issue(key, "a", [], DER, NOW, aud="other")
    assert reason(t, key.public_key()) == "bad_audience"


def test_alg_none_rejected(key):
    claims = {"sub": "a", "aud": "api.demo", "exp": NOW + 300}
    t = jwt.encode(claims, None, algorithm="none")
    assert reason(t, key.public_key()) == "bad_signature"


def test_hs256_with_public_key_bytes_rejected(key):
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    claims = {"sub": "a", "aud": "api.demo", "exp": NOW + 300}
    # PyJWT refuses to sign with a PEM secret, so forge the token by hand like an attacker
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    signing = b64(b'{"alg":"HS256","typ":"JWT"}') + "." + b64(json.dumps(claims).encode())
    mac = hmac.new(pem, signing.encode(), hashlib.sha256).digest()
    t = signing + "." + b64(mac)
    assert reason(t, key.public_key()) == "bad_signature"


def test_garbage_is_malformed(key):
    assert reason("garbage", key.public_key()) == "malformed"

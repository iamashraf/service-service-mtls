import asyncio

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app import binding, guard, policy, tokens
from app.guard import AuthError

NOW = 1_000_000
DER = b"client-cert-der"
OTHER_DER = b"other-cert-der"
KEY = ec.generate_private_key(ec.SECP256R1())
KID = "k1"


async def resolve(kid):
    return KEY.public_key() if kid == KID else None


def good_claims(**over):
    c = {
        "iss": tokens.ISS, "sub": "java-writer", "aud": "api.demo",
        "exp": NOW + 300, "scope": "orders:read orders:write",
        "cnf": {"x5t#S256": binding.thumbprint(DER)},
    }
    c.update(over)
    return c


def sign(claims, key=KEY):
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": KID})


def bearer(claims, key=KEY):
    return "Bearer " + sign(claims, key)


def run(peer=DER, auth=None, scope="orders:read", now=NOW):
    return asyncio.run(guard.authorize(peer, auth, scope, resolve, now))


def fail(**kw):
    with pytest.raises(AuthError) as e:
        run(**kw)
    return e.value.reason, e.value.status


def test_ok():
    c = run(auth=bearer(good_claims()))
    assert c["sub"] == "java-writer"


def test_lowercase_scheme_accepted():
    assert run(auth="bearer " + sign(good_claims()))["sub"] == "java-writer"


def test_thumbprint_mismatch():
    assert fail(peer=OTHER_DER, auth=bearer(good_claims())) == ("thumbprint_mismatch", 401)


@pytest.mark.parametrize("cnf", [
    "MISSING", {}, {"x5t#S256": ""}, {"x5t#S256": 5}, "str", None, [], {"other": "x"},
])
def test_no_cnf(cnf):
    c = good_claims()
    if cnf == "MISSING":
        del c["cnf"]
    else:
        c["cnf"] = cnf
    assert fail(auth=bearer(c)) == ("no_cnf", 401)


def test_bad_signature():
    other = ec.generate_private_key(ec.SECP256R1())
    assert fail(auth=bearer(good_claims(), other)) == ("bad_signature", 401)


def test_expired():
    assert fail(auth=bearer(good_claims(exp=NOW - 1))) == ("expired", 401)


def test_bad_audience():
    assert fail(auth=bearer(good_claims(aud="x"))) == ("bad_audience", 401)


@pytest.mark.parametrize("peer", [None, b""])
def test_no_client_cert(peer):
    assert fail(peer=peer, auth=bearer(good_claims())) == ("no_client_cert", 401)


@pytest.mark.parametrize("auth", [None, "", "Basic x", "Bearer ", "Bearer garbage"])
def test_malformed(auth):
    assert fail(auth=auth) == ("malformed", 401)


def test_insufficient_scope_is_403():
    c = good_claims(scope="orders:read")
    assert fail(auth=bearer(c), scope="orders:write") == ("insufficient_scope", 403)


def test_scope_check_is_exact_token_match():
    c = good_claims(scope="orders:readonly")
    assert fail(auth=bearer(c), scope="orders:read")[0] == "insufficient_scope"


def test_missing_kid_is_malformed():
    t = jwt.encode(good_claims(), KEY, algorithm="ES256")
    assert fail(auth="Bearer " + t) == ("malformed", 401)


def test_unknown_kid_is_bad_signature():
    t = jwt.encode(good_claims(), KEY, algorithm="ES256", headers={"kid": "nope"})
    assert fail(auth="Bearer " + t) == ("bad_signature", 401)


def test_issue_scopes_come_from_policy_only():
    import inspect
    assert "scopes" in inspect.signature(tokens.issue).parameters  # caller passes policy output
    assert policy.scopes_for("java-reader") == ["orders:read"]
    assert policy.scopes_for("java-writer") == ["orders:read", "orders:write"]
    assert policy.scopes_for("rogue") is None
    # no scope-like parameter on any request-facing entry point
    assert "scope" not in inspect.signature(policy.scopes_for).parameters

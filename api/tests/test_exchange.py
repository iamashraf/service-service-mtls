"""Token exchange rules, tested on the pure function (no HTTP)."""
import asyncio

import pytest

from app import binding, tokens
from app.exchange import ACCESS_TOKEN, ExchangeError, exchange
from app.keys import KeySet

NOW = 1_000_000
WRITER_DER, READER_DER = b"writer-der", b"reader-der"
keys = KeySet()


async def resolve(kid):
    return keys.public(kid)


def mint(sub, scopes, aud, cnf):
    kid, key = keys.current
    return tokens.issue(key, sub, scopes, None, NOW, aud, kid=kid, cnf=cnf)


def subject(der=WRITER_DER, sub="java-writer", scopes=("orders:read", "orders:write"), **kw):
    kid, key = keys.current
    return tokens.issue(key, sub, list(scopes), der, NOW, kid=kid, **kw)


def form(**over):
    f = {"subject_token": subject(), "subject_token_type": ACCESS_TOKEN, "audience": "api.demo"}
    f.update(over)
    return {k: v for k, v in f.items() if v is not None}


def run(f, der=WRITER_DER, cn="java-writer", now=NOW):
    return asyncio.run(exchange(f, der, cn, resolve, mint, now))


def err(f, **kw):
    with pytest.raises(ExchangeError) as e:
        run(f, **kw)
    return e.value.code, e.value.desc


def claims_of(out):
    return asyncio.run(tokens.verify(out["access_token"], resolve, "api.demo", NOW))


def test_default_scope_is_subject_scope():
    out = run(form())
    assert out["scope"] == "orders:read orders:write" and out["token_type"] == "Bearer"
    assert out["issued_token_type"] == ACCESS_TOKEN and out["expires_in"] == 300


def test_narrows_and_copies_cnf():
    out = run(form(scope="orders:read"))
    c = claims_of(out)
    assert out["scope"] == "orders:read" and c["scope"] == "orders:read"
    assert c["cnf"] == {"x5t#S256": binding.thumbprint(WRITER_DER)} and c["sub"] == "java-writer"


def test_reader_cannot_widen_to_write():
    f = form(subject_token=subject(READER_DER, "java-reader", ["orders:read"]), scope="orders:write")
    assert err(f, der=READER_DER, cn="java-reader") == ("invalid_scope", "scope_not_allowed")


def test_scope_subset_of_policy_even_if_subject_claims_more():
    # a token that claims more than policy allows today is not widened by exchange
    f = form(subject_token=subject(READER_DER, "java-reader", ["orders:read", "orders:write"]))
    assert err(f, der=READER_DER, cn="java-reader")[0] == "invalid_scope"


def test_other_cert_presenting_subject_token():
    assert err(form(), der=READER_DER, cn="java-reader") == ("invalid_grant", "thumbprint_mismatch")


def test_unknown_audience():
    assert err(form(audience="other.demo")) == ("invalid_target", "audience_not_allowed")


@pytest.mark.parametrize("over", [{"subject_token": None}, {"audience": None},
                                  {"subject_token_type": "urn:x"}, {"subject_token_type": None}])
def test_invalid_request(over):
    assert err(form(**over))[0] == "invalid_request"


def test_bad_subject_tokens_are_invalid_grant_with_reason():
    assert err(form(subject_token="garbage")) == ("invalid_grant", "malformed")
    old = tokens.issue(keys.current[1], "a", [], WRITER_DER, NOW - 400, kid=keys.current[0])
    assert err(form(subject_token=old)) == ("invalid_grant", "expired")
    assert err(form(subject_token=subject(aud="other"))) == ("invalid_grant", "bad_audience")
    assert err(form(subject_token=subject(iss="https://evil"))) == ("invalid_grant", "bad_issuer")
    forged = tokens.issue(KeySet().current[1], "a", [], WRITER_DER, NOW, kid="x")
    assert err(form(subject_token=forged)) == ("invalid_grant", "bad_signature")


def test_check_order_subject_before_thumbprint_before_audience_before_scope():
    bad = form(subject_token="garbage", audience="other.demo", scope="orders:admin")
    assert err(bad, der=READER_DER)[0] == "invalid_grant"
    ok_subject = form(audience="other.demo", scope="orders:admin")
    assert err(ok_subject, der=READER_DER) == ("invalid_grant", "thumbprint_mismatch")
    assert err(ok_subject)[0] == "invalid_target"
    assert err(form(scope="orders:admin"))[0] == "invalid_scope"

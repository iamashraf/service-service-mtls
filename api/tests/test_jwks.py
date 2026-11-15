"""JWKS cache and key rotation, with a fake clock and a fake fetcher."""
import asyncio

import pytest

from app import tokens
from app.guard import AuthError
from app.jwks import JwksClient
from app.keys import KeySet

NOW = 1_000_000


class Fake:
    """A fetcher that serves keys.jwks() and counts calls; `fail` makes it raise."""

    def __init__(self, keys):
        self.keys, self.calls, self.fail, self.t = keys, 0, False, 0.0

    async def fetch(self):
        self.calls += 1
        if self.fail:
            raise OSError("auth down")
        return self.keys.jwks()

    def now(self):
        return self.t


def setup(**kw):
    keys = KeySet()
    f = Fake(keys)
    return keys, f, JwksClient(f.fetch, f.now, **kw)


def tok(keys, kid=None):
    k, key = keys.current if kid is None else (kid, keys._keys[[i for i, _ in keys._keys].index(kid)][1])
    return tokens.issue(key, "a", [], b"der", NOW, kid=k)


def check(client, token):
    return asyncio.run(tokens.verify(token, client.get, "api.demo", NOW))


def reason(client, token):
    with pytest.raises(AuthError) as e:
        check(client, token)
    return e.value.reason


def test_cache_is_used_until_ttl():
    keys, f, c = setup(ttl=300)
    t = tok(keys)
    check(c, t); check(c, t)
    assert f.calls == 1
    f.t = 299; check(c, t)
    assert f.calls == 1
    f.t = 301; check(c, t)
    assert f.calls == 2


def test_unknown_kid_refetches_at_most_once_per_interval():
    keys, f, c = setup(min_refetch=10)
    check(c, tok(keys))
    forged = tokens.issue(KeySet().current[1], "a", [], b"d", NOW, kid="evil")
    for _ in range(5):
        assert reason(c, forged) == "bad_signature"
    assert f.calls == 1  # the first fetch was less than 10s ago
    f.t = 11
    assert reason(c, forged) == "bad_signature"
    assert f.calls == 2
    for _ in range(5):
        reason(c, forged)
    assert f.calls == 2


def test_fetch_failure_keeps_old_keys_and_retries_later():
    keys, f, c = setup(ttl=300, min_refetch=10)
    t = tok(keys)
    check(c, t)
    f.fail, f.t = True, 301
    check(c, t)  # stale but still served
    assert f.calls == 2
    check(c, t)  # inside the min interval: no new call
    assert f.calls == 2
    f.fail, f.t = False, 312
    check(c, t)
    assert f.calls == 3


def test_first_fetch_failure_is_bad_signature_then_recovers():
    keys, f, c = setup(min_refetch=10)
    f.fail = True
    assert reason(c, tok(keys)) == "bad_signature"
    f.fail, f.t = False, 11
    check(c, tok(keys))


def test_rotation_old_and_new_verify_and_retired_does_not():
    keys, f, c = setup(ttl=300, min_refetch=10)
    old_kid = keys.current[0]
    old = tok(keys)
    check(c, old)
    new_kid = keys.rotate()
    new = tok(keys)
    f.t = 11  # unknown new kid forces a refetch
    check(c, new)
    check(c, old)  # previous key is still published
    assert {k["kid"] for k in keys.jwks()["keys"]} == {old_kid, new_kid}
    keys.rotate()  # old_kid is now retired
    f.t = 400  # TTL passed: cache refreshes and drops it
    assert reason(c, old) == "bad_signature"
    check(c, new)


def test_jwks_document_shape():
    keys = KeySet()
    keys.rotate()
    doc = keys.jwks()
    assert len(doc["keys"]) == 2
    for k in doc["keys"]:
        assert k["kty"] == "EC" and k["crv"] == "P-256" and k["alg"] == "ES256" and k["use"] == "sig"
        assert k["kid"] and k["x"] and k["y"] and "d" not in k

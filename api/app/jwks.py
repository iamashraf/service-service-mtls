"""JWKS client for the api: fetch the auth server's keys over mTLS and cache them."""
import asyncio
import logging
import ssl
import time

import httpx
import jwt

log = logging.getLogger("app")


def mtls_fetcher(url: str, certfile: str, keyfile: str, cafile: str):
    """Return an async fetcher that GETs `url` with our own cert, trusting only the demo CA."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    client = httpx.AsyncClient(verify=ctx, timeout=5)

    async def fetch() -> dict:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()
    return fetch


class JwksClient:
    """kid -> public key. A cached key is used until `ttl` seconds pass. An unknown kid
    forces one refetch, but never more often than every `min_refetch` seconds, so bad
    tokens cannot make the api hammer the auth server. `fetch` and `now` are injectable."""

    def __init__(self, fetch, now=time.monotonic, ttl: float = 300, min_refetch: float = 10):
        self._fetch, self._now, self.ttl, self.min_refetch = fetch, now, ttl, min_refetch
        self._keys: dict = {}
        self._fetched: float | None = None   # last successful fetch
        self._attempt: float | None = None   # last try, ok or not
        self._lock = asyncio.Lock()

    async def refresh(self) -> None:
        """Fetch now. On failure keep the old keys, log, and let the caller retry later."""
        self._attempt = self._now()
        try:
            doc = await self._fetch()
            self._keys = {k["kid"]: jwt.PyJWK(k).key for k in doc["keys"]}
        except Exception as e:  # network, status, or a bad document: fail closed on new kids
            log.warning("JWKS fetch failed: %s", e)
            return
        self._fetched = self._attempt
        log.info("JWKS fetch OK kids=%s", sorted(self._keys))

    async def get(self, kid: str):
        """Public key for `kid`, or None if the auth server does not publish it."""
        async with self._lock:
            t = self._now()
            stale = self._fetched is None or t - self._fetched >= self.ttl
            if (stale or kid not in self._keys) and (
                    self._attempt is None or t - self._attempt >= self.min_refetch):
                await self.refresh()
            return self._keys.get(kid)

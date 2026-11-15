"""Resource server entry point: enroll, then serve mTLS; keys come from auth's JWKS."""
import asyncio
import os

from . import boot
from .jwks import JwksClient, mtls_fetcher
from .main import create_app


def main() -> None:
    """Enroll as api.demo and serve. The api holds no signing key and no policy."""
    paths = boot.bootstrap("api.demo")
    auth_url = os.environ.get("AUTH_URL", "https://auth.demo:8443")
    jwks = JwksClient(mtls_fetcher(f"{auth_url}/.well-known/jwks.json", *paths))

    async def run() -> None:
        await jwks.refresh()  # warm the cache; a failure is logged and retried on demand
        await boot.serve_mtls(create_app(jwks.get), paths)
    asyncio.run(run())


if __name__ == "__main__":
    main()

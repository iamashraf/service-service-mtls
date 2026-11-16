"""Resource server entry point: enroll, then serve mTLS; keys come from auth's JWKS."""
import asyncio
import logging
import os

from . import boot
from .grpc_server import create_server
from .jwks import JwksClient, mtls_fetcher
from .main import create_app


def main() -> None:
    """Enroll as api.demo and serve REST (:8443) and gRPC (:9443). The api holds no signing key."""
    paths = boot.bootstrap("api.demo")
    auth_url = os.environ.get("AUTH_URL", "https://auth.demo:8443")
    jwks = JwksClient(mtls_fetcher(f"{auth_url}/.well-known/jwks.json", *paths))

    async def run() -> None:
        await jwks.refresh()  # warm the cache; a failure is logged and retried on demand
        orders: list[str] = []  # one store for both protocols; one event loop, so no lock
        grpc_server, port = create_server(orders, jwks.get, paths, int(os.environ.get("GRPC_PORT", "9443")))
        await grpc_server.start()
        logging.getLogger("app").info("gRPC listening on :%d", port)
        await boot.serve_mtls(create_app(jwks.get, orders=orders), paths)
        await grpc_server.stop(2)
    asyncio.run(run())


if __name__ == "__main__":
    main()

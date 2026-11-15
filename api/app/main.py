"""Resource server: /orders is protected by scope. Tokens come from the auth server."""
import os
import time

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from . import dpop, guard, tls
from .web import install_error_handlers, log_decision


class OrderIn(BaseModel):
    """Body of POST /orders."""

    item: str


def create_app(resolve, now=time.time, orders: list[str] | None = None) -> FastAPI:
    """Build the app. `resolve` is an async kid -> public key (the JWKS cache); `now` is a clock.

    `orders` is the shared order list (the gRPC server gets the same object)."""
    app = FastAPI()
    public = os.environ.get("API_PUBLIC_URL", "https://api.demo:8443")  # htu base, never the Host header
    cache = dpop.JtiCache()
    orders = [] if orders is None else orders

    install_error_handlers(app)

    def require(scope: str):
        """Dependency that runs the guard. Handlers read the body themselves, after this
        passes, so an unauthenticated caller gets 401 for any body, never 422 or 400.
        The handler logs the allow, so a request that then fails validation logs once."""
        async def check(request: Request, authorization: str | None = Header(None)) -> None:
            """Run the guard for the current connection's cert. Raises AuthError on failure."""
            ident = tls.peer_identity()
            await guard.authorize(ident[0] if ident else None, authorization, scope,
                                  resolve, int(now()),
                                  (request.headers.getlist("dpop"), request.method,
                                   public + request.url.path, cache))
        return Depends(check)

    @app.get("/orders", dependencies=[require("orders:read")])
    async def list_orders():
        """List orders. Needs orders:read."""
        log_decision(tls.peer_identity(), "allow", "ok")
        return {"orders": orders}

    @app.post("/orders", status_code=201, dependencies=[require("orders:write")])
    async def add_order(request: Request):
        """Add an order. Needs orders:write. The body is parsed only after auth passes."""
        try:
            order = OrderIn.model_validate_json(await request.body())
        except ValidationError:
            log_decision(tls.peer_identity(), "deny", "invalid_body")
            return JSONResponse({"error": "invalid_body"}, status_code=422)
        orders.append(order.item)
        log_decision(tls.peer_identity(), "allow", "ok")
        return {"orders": orders}

    return app

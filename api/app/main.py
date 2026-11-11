"""FastAPI app: /token mints cert-bound tokens, /orders is protected by scope."""
import logging
import time

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import binding, guard, policy, tls, tokens
from .guard import AuthError

log = logging.getLogger("app")


class OrderIn(BaseModel):
    """Body of POST /orders."""

    item: str


def _log(ident, decision: str, reason: str) -> None:
    """One line per request: quoted CN, thumbprint prefix, decision, reason."""
    cn = ident[1] if ident else None
    tp = binding.thumbprint(ident[0])[:8] if ident else "-"
    log.info("cn=%r thumbprint=%s decision=%s reason=%s", cn, tp, decision, reason)


def create_app(signing_key, now=time.time) -> FastAPI:
    """Build the app. `signing_key` is the ES256 key; `now` is a clock returning seconds."""
    app = FastAPI()
    orders: list[str] = []

    @app.exception_handler(AuthError)
    async def auth_error(request: Request, exc: AuthError):
        """Map a failed check to JSON {"error": reason} with its status, and log it."""
        _log(tls.peer_identity(), "deny", exc.reason)
        return JSONResponse({"error": exc.reason}, status_code=exc.status)

    def check(required: str, authorization: str | None) -> None:
        """Run the guard for the current connection's cert and log the allow."""
        ident = tls.peer_identity()
        guard.authorize(ident[0] if ident else None, authorization, required,
                        signing_key.public_key(), int(now()))
        _log(ident, "allow", "ok")

    @app.post("/token")
    async def token():
        """Issue a token bound to the client cert. Scopes come from policy only."""
        ident = tls.peer_identity()
        if not ident:
            raise AuthError("no_client_cert", 401)
        der, cn = ident
        # scopes are looked up by the verified CN, never read from the request
        scopes = policy.scopes_for(cn)
        if scopes is None:
            raise AuthError("no_policy", 403)
        tok = tokens.issue(signing_key, cn, scopes, der, int(now()))
        _log(ident, "allow", "ok")
        return {"access_token": tok, "token_type": "Bearer", "expires_in": tokens.TTL}

    @app.get("/orders")
    async def list_orders(authorization: str | None = Header(None)):
        """List orders. Needs orders:read."""
        check("orders:read", authorization)
        return {"orders": orders}

    @app.post("/orders", status_code=201)
    async def add_order(order: OrderIn, authorization: str | None = Header(None)):
        """Add an order. Needs orders:write."""
        check("orders:write", authorization)
        orders.append(order.item)
        return {"orders": orders}

    return app

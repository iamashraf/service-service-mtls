"""FastAPI app: /token mints cert-bound tokens, /orders is protected by scope."""
import logging
import time

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

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

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        """Log and return routing errors (404, 405) as JSON {"error": "http_<status>"}."""
        _log(tls.peer_identity(), "deny", f"http_{exc.status_code}")
        return JSONResponse({"error": f"http_{exc.status_code}"}, status_code=exc.status_code,
                            headers=exc.headers)

    def require(scope: str):
        """Dependency that runs the guard. Handlers read the body themselves, after this
        passes, so an unauthenticated caller gets 401 for any body, never 422 or 400.
        The handler logs the allow, so a request that then fails validation logs once."""
        async def check(authorization: str | None = Header(None)) -> None:
            """Run the guard for the current connection's cert. Raises AuthError on failure."""
            ident = tls.peer_identity()
            guard.authorize(ident[0] if ident else None, authorization, scope,
                            signing_key.public_key(), int(now()))
        return Depends(check)

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

    @app.get("/orders", dependencies=[require("orders:read")])
    async def list_orders():
        """List orders. Needs orders:read."""
        _log(tls.peer_identity(), "allow", "ok")
        return {"orders": orders}

    @app.post("/orders", status_code=201, dependencies=[require("orders:write")])
    async def add_order(request: Request):
        """Add an order. Needs orders:write. The body is parsed only after auth passes."""
        try:
            order = OrderIn.model_validate_json(await request.body())
        except ValidationError:
            _log(tls.peer_identity(), "deny", "invalid_body")
            return JSONResponse({"error": "invalid_body"}, status_code=422)
        orders.append(order.item)
        _log(tls.peer_identity(), "allow", "ok")
        return {"orders": orders}

    return app

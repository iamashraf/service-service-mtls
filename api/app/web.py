"""Pieces both services share: the one-line request log and JSON error handlers."""
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import binding, tls
from .guard import AuthError

log = logging.getLogger("app")


def log_decision(ident, decision: str, reason: str) -> None:
    """One line per request: quoted CN, thumbprint prefix, decision, reason."""
    cn = ident[1] if ident else None
    tp = binding.thumbprint(ident[0])[:8] if ident else "-"
    log.info("cn=%r thumbprint=%s decision=%s reason=%s", cn, tp, decision, reason)


def install_error_handlers(app: FastAPI) -> None:
    """Map AuthError and routing errors to JSON {"error": ...} and log them."""

    @app.exception_handler(AuthError)
    async def auth_error(request: Request, exc: AuthError):
        """Map a failed check to JSON {"error": reason} with its status, and log it."""
        log_decision(tls.peer_identity(), "deny", exc.reason)
        return JSONResponse({"error": exc.reason}, status_code=exc.status)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        """Log and return routing errors (404, 405) as JSON {"error": "http_<status>"}."""
        log_decision(tls.peer_identity(), "deny", f"http_{exc.status_code}")
        return JSONResponse({"error": f"http_{exc.status_code}"}, status_code=exc.status_code,
                            headers=exc.headers)

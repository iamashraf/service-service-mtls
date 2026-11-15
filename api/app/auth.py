"""Auth server: issues cert-bound tokens, publishes JWKS, exchanges tokens (RFC 8693)."""
import asyncio
import time
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import boot, exchange, policy, tls, tokens
from .guard import AuthError
from .keys import KeySet
from .web import install_error_handlers, log_decision


def create_app(keys: KeySet, now=time.time) -> FastAPI:
    """Build the app. `keys` holds the signing keys; `now` is a clock returning seconds."""
    app = FastAPI()
    install_error_handlers(app)

    async def resolve(kid: str):
        return keys.public(kid)

    def mint(sub, scopes, aud, cnf) -> str:
        kid, key = keys.current
        return tokens.issue(key, sub, scopes, None, int(now()), aud, kid=kid, cnf=cnf)

    # the mTLS handshake already limits these two to certs from the demo CA
    @app.get("/.well-known/jwks.json")
    async def jwks():
        """Public signing keys."""
        return keys.jwks()

    @app.get("/.well-known/oauth-authorization-server")
    async def metadata():
        """RFC 8414 metadata."""
        return {"issuer": tokens.ISS, "token_endpoint": f"{tokens.ISS}/token",
                "jwks_uri": f"{tokens.ISS}/.well-known/jwks.json",
                "grant_types_supported": ["client_credentials", exchange.GRANT],
                "token_endpoint_auth_methods_supported": ["tls_client_auth"],
                "tls_client_certificate_bound_access_tokens": True}

    @app.post("/token")
    async def token(request: Request):
        """Initial token or RFC 8693 exchange. Scopes come from policy only, never the body."""
        ident = tls.peer_identity()
        if not ident:
            raise AuthError("no_client_cert", 401)
        der, cn = ident
        form = dict(parse_qsl((await request.body()).decode(errors="replace"),
                              keep_blank_values=True))
        grant = form.get("grant_type")
        if grant == exchange.GRANT:
            try:
                out = await exchange.exchange(form, der, cn, resolve, mint, int(now()))
            except exchange.ExchangeError as e:
                log_decision(ident, "deny", e.desc)
                return JSONResponse({"error": e.code, "error_description": e.desc}, status_code=400)
            log_decision(ident, "allow", "ok")
            return out
        if grant not in (None, "client_credentials"):
            log_decision(ident, "deny", "unsupported_grant_type")
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        # scopes are looked up by the verified CN, never read from the request
        scopes = policy.scopes_for(cn)
        if scopes is None:
            raise AuthError("no_policy", 403)
        kid, key = keys.current
        tok = tokens.issue(key, cn, scopes, der, int(now()), policy.audiences_for(cn)[0], kid=kid)
        log_decision(ident, "allow", "ok")
        return {"access_token": tok, "token_type": "Bearer", "expires_in": tokens.TTL,
                "scope": " ".join(scopes)}

    return app


def main() -> None:
    """Enroll as auth.demo and serve. Keys live in memory; a restart invalidates old tokens."""
    paths = boot.bootstrap("auth.demo")
    asyncio.run(boot.serve_mtls(create_app(KeySet()), paths))


if __name__ == "__main__":
    main()

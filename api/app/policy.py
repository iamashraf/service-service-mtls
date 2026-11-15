"""Auth-server policy by cert CN. The only source of token scopes and audiences."""

_POLICY = {
    "java-writer": {"scopes": ["orders:read", "orders:write"], "audiences": ["api.demo"]},
    "java-reader": {"scopes": ["orders:read"], "audiences": ["api.demo"]},
}


def scopes_for(cn: str) -> list[str] | None:
    """Return the scopes for a cert CN, or None if the CN has no policy."""
    p = _POLICY.get(cn)
    return list(p["scopes"]) if p else None


def audiences_for(cn: str) -> list[str]:
    """Return the audiences a CN may ask tokens for (empty if no policy)."""
    p = _POLICY.get(cn)
    return list(p["audiences"]) if p else []

"""Server-side scope policy. The only source of token scopes."""

_POLICY = {
    "java-writer": ["orders:read", "orders:write"],
    "java-reader": ["orders:read"],
}


def scopes_for(cn: str) -> list[str] | None:
    """Return the scopes for a cert CN, or None if the CN has no policy."""
    scopes = _POLICY.get(cn)
    return list(scopes) if scopes is not None else None

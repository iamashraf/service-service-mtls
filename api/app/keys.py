"""Auth server signing keys: up to two ES256 keys with a kid, so a rotation overlaps."""
import secrets

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


class KeySet:
    """The newest key signs. The previous key stays published until the next rotation."""

    def __init__(self):
        self._keys: list[tuple[str, ec.EllipticCurvePrivateKey]] = []
        self.rotate()

    def rotate(self) -> str:
        """Add a new signing key, keep the previous one, drop older ones. Returns the new kid."""
        kid = secrets.token_hex(8)
        self._keys = (self._keys + [(kid, ec.generate_private_key(ec.SECP256R1()))])[-2:]
        return kid

    @property
    def current(self) -> tuple[str, ec.EllipticCurvePrivateKey]:
        """(kid, private key) used to sign new tokens."""
        return self._keys[-1]

    def public(self, kid: str):
        """The public key for `kid`, or None if it is not (or no longer) published."""
        return next((k.public_key() for i, k in self._keys if i == kid), None)

    def jwks(self) -> dict:
        """The JWK Set document (public keys only)."""
        return {"keys": [{**jwt.algorithms.ECAlgorithm.to_jwk(k.public_key(), as_dict=True),
                          "kid": i, "alg": "ES256", "use": "sig"} for i, k in self._keys]}

"""Key providers: resolve a key ID to raw key material. They belong to a local
backend, since a remote service that encrypts for you exposes no key material."""

from ..interfaces import KeyProvider
from .environment import EnvironmentKeyProvider

__all__ = ["EnvironmentKeyProvider", "KeyProvider"]

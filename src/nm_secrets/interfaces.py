"""Abstract contracts the generic layer depends on.

Kept here, not inside a concrete backend or provider, so the handler and the
concrete implementations import them downward rather than the handler importing
its own core type from one specific algorithm.
"""

from typing import Protocol


class KeyProvider(Protocol):
    """Resolves a key ID to raw key material. Belongs to a local backend; a
    remote service that encrypts for you exposes no key material, so has none."""

    def get_key(self, key_id: str) -> bytes: ...


class SecretCipherBackend(Protocol):
    """Performs the encryption behind an envelope. Receives already-validated
    plaintext bytes and an opaque ``aad`` it cannot vary."""

    @property
    def backend_id(self) -> str: ...

    def encrypt(self, plaintext: bytes, *, key_id: str, aad: bytes) -> str: ...

    def decrypt(self, payload: str, *, key_id: str, aad: bytes) -> bytes: ...

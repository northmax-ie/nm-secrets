"""The aes256gcm backend: payload = urlsafe_base64(nonce || ciphertext || tag).

AES-256-GCM via cryptography's AESGCM; 32-byte key, a fresh 12-byte os.urandom
nonce per call, 16-byte tag. No method takes a nonce or IV: such a parameter is
how GCM nonce reuse happens.
"""

import os
import base64
import binascii

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import (
    SecretConfigurationError,
    SecretDecryptionError,
    SecretEncryptionError,
    SecretFormatError,
)
from ..interfaces import KeyProvider

_BACKEND_ID = "aes256gcm"
_KEY_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16


class AES256GCMBackend:
    """AES-256-GCM backend resolving key material through a local provider."""

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider

    @property
    def backend_id(self) -> str:
        return _BACKEND_ID

    def _resolve_key(self, key_id: str) -> bytes:
        key = self._provider.get_key(key_id)
        # Require bytes of exactly 32; AESGCM also accepts 128/192-bit keys, and a
        # non-bytes value would otherwise reach the primitive as a raw TypeError.
        # A defective provider is a configuration error, both ways.
        if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
            raise SecretConfigurationError(
                f"key material for key_id {key_id!r} is not {_KEY_BYTES} bytes"
            ) from None
        return key

    def encrypt(self, plaintext: bytes, *, key_id: str, aad: bytes) -> str:
        key = self._resolve_key(key_id)
        try:
            # os.urandom inside the boundary: a random-source failure is an
            # unexpected encryption failure, not an uncaught OSError.
            nonce = os.urandom(_NONCE_BYTES)
            sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
        except Exception:
            raise SecretEncryptionError("encryption failed") from None
        return base64.urlsafe_b64encode(nonce + sealed).decode("ascii")

    def decrypt(self, payload: str, *, key_id: str, aad: bytes) -> bytes:
        key = self._resolve_key(key_id)

        try:
            # Strict decode: urlsafe_b64decode has no validate=, and non-strict
            # mode silently drops non-alphabet characters before checking padding.
            raw = base64.b64decode(payload, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            raise SecretFormatError("payload is not valid Base64") from None

        if len(raw) < _NONCE_BYTES + _TAG_BYTES:
            raise SecretFormatError("payload is too short") from None

        nonce, sealed = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]

        try:
            return AESGCM(key).decrypt(nonce, sealed, aad)
        except InvalidTag:
            raise SecretDecryptionError("authentication failed") from None

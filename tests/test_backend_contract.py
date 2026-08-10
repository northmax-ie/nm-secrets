"""Backend contract: the backend_id property and error classification.

The exception hierarchy is a first-class concern: SecretEncryptionError must
cover an unexpected backend failure only, and must never wrap a configuration or
format error. These tests pin that classification.
"""

import base64

import pytest

from nm_secrets import (
    AES256GCMBackend,
    EnvironmentKeyProvider,
    SecretConfigurationError,
    SecretEncryptionError,
    SecretFormatError,
    SecretHandler,
)

from .helpers import CURRENT_KEY_ID


class _NonBytesKeyProvider:
    """Returns a 32-length value that is not bytes."""

    def get_key(self, key_id: str) -> bytes:
        return "x" * 32  # type: ignore[return-value]


def test_non_bytes_key_material_raises_configuration_error_both_paths():
    # len == 32 but not bytes. Without the isinstance guard, encrypt would map to
    # SecretEncryptionError and decrypt would leak a raw TypeError; both must be
    # SecretConfigurationError.
    backend = AES256GCMBackend(_NonBytesKeyProvider())
    # A payload long enough to pass the length check and reach the primitive.
    payload = base64.urlsafe_b64encode(b"z" * 40).decode("ascii")
    with pytest.raises(SecretConfigurationError):
        backend.encrypt(b"plaintext", key_id="gen2", aad=b"aad")
    with pytest.raises(SecretConfigurationError):
        backend.decrypt(payload, key_id="gen2", aad=b"aad")


class _BytesPayloadBackend:
    """A backend that returns bytes instead of str from encrypt."""

    backend_id = "aes256gcm"

    def encrypt(self, plaintext: bytes, *, key_id: str, aad: bytes) -> str:
        return b"payload"  # type: ignore[return-value]

    def decrypt(self, payload: str, *, key_id: str, aad: bytes) -> bytes:  # pragma: no cover
        raise AssertionError("not called")


def test_non_string_backend_payload_becomes_encryption_error():
    # A backend returning bytes would otherwise be stringified into a malformed
    # envelope; the handler rejects it instead.
    handler = SecretHandler(
        namespace="x", backends=[_BytesPayloadBackend()], current_key_id="gen1"
    )
    with pytest.raises(SecretEncryptionError):
        handler.encrypt("hi", name="n")


def test_backend_id_property():
    backend = AES256GCMBackend(EnvironmentKeyProvider())
    assert backend.backend_id == "aes256gcm"


def test_unexpected_encrypt_failure_becomes_encryption_error(env_keys, monkeypatch):
    class _BoomAESGCM:
        def __init__(self, key):
            pass

        def encrypt(self, nonce, data, aad):
            raise RuntimeError("primitive blew up")

    monkeypatch.setattr("nm_secrets.backends.aes256gcm.AESGCM", _BoomAESGCM)

    backend = AES256GCMBackend(EnvironmentKeyProvider())
    with pytest.raises(SecretEncryptionError) as excinfo:
        backend.encrypt(b"plaintext", key_id=CURRENT_KEY_ID, aad=b"aad")

    exc = excinfo.value
    # The narrow wrapper must not flatten config or format errors into itself,
    # and must not leak the underlying cause.
    assert not isinstance(exc, (SecretConfigurationError, SecretFormatError))
    assert exc.__cause__ is None
    assert exc.__suppress_context__ is True

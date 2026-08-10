"""Configuration and identifier validation."""

import pytest

from nm_secrets import (
    AES256GCMBackend,
    EnvironmentKeyProvider,
    SecretConfigurationError,
    SecretFormatError,
    SecretHandler,
)
from nm_secrets import envelope as envelope_module

from .helpers import CURRENT_KEY_ID, SHORT_KEY_ID, RelabeledBackend

_BACKEND = AES256GCMBackend(EnvironmentKeyProvider())


class _ShortKeyProvider:
    """A deliberately defective provider that returns 16-byte key material.

    Used to reach the backend's own key-length guard. EnvironmentKeyProvider
    rejects a wrong-length key before the backend sees it, so only a stub
    provider like this exercises the backend check that stops AES-128 from
    slipping through under an aes256gcm envelope.
    """

    def get_key(self, key_id: str) -> bytes:
        return b"sixteen-byte-key"  # 16 bytes


def _construct(current_backend_id=None, current_key_id=CURRENT_KEY_ID, backends=None):
    if backends is None:
        backends = [_BACKEND]
    return SecretHandler(
        namespace="enclave",
        backends=backends,
        current_key_id=current_key_id,
        current_backend_id=current_backend_id,
    )


@pytest.mark.parametrize("bad_key_id", ["key:1", "key-1"])
def test_invalid_key_id_rejected_at_construction(bad_key_id):
    with pytest.raises(SecretConfigurationError):
        _construct(current_key_id=bad_key_id)


def test_non_string_current_key_id_rejected_at_construction():
    # A non-string identifier must be a SecretConfigurationError, not a raw
    # TypeError from the validating regex.
    with pytest.raises(SecretConfigurationError):
        _construct(current_key_id=123)


def test_backend_reporting_non_string_backend_id_rejected_at_construction():
    with pytest.raises(SecretConfigurationError):
        _construct(backends=[RelabeledBackend(_BACKEND, 123)])


def test_backend_reporting_invalid_backend_id_rejected_at_construction():
    # The handler keys backends by their self-reported backend_id, so a backend
    # reporting an id outside the grammar (here, one containing "_") is rejected
    # at construction.
    with pytest.raises(SecretConfigurationError):
        _construct(backends=[RelabeledBackend(_BACKEND, "aes_gcm")])


def test_duplicate_backend_id_rejected_at_construction():
    # Two backends reporting the same id would otherwise collapse silently in the
    # internal map; construction rejects the collision.
    with pytest.raises(SecretConfigurationError):
        _construct(backends=[_BACKEND, RelabeledBackend(_BACKEND, "aes256gcm")])


def test_current_backend_id_defaults_to_sole_backend(env_keys):
    # Omitted current_backend_id resolves to the only registered backend.
    handler = _construct()
    envelope = handler.encrypt("v", name="n")
    assert envelope_module.parse(envelope).backend_id == "aes256gcm"


def test_current_backend_id_required_with_multiple_backends():
    # With more than one backend, "current" is a real choice and must be given.
    with pytest.raises(SecretConfigurationError):
        _construct(backends=[_BACKEND, RelabeledBackend(_BACKEND, "altbackend")])


def test_traversal_key_id_rejected_during_parsing():
    with pytest.raises(SecretFormatError):
        envelope_module.parse("ENC[v1:aes256gcm:../../secret:payload]")


def test_invalid_backend_id_in_envelope_rejected_during_parsing():
    # Uppercase is outside the backend_id grammar; rejected at the envelope
    # layer before any dispatch.
    with pytest.raises(SecretFormatError):
        envelope_module.parse("ENC[v1:AES256GCM:gen2:payload]")


def test_unconfigured_current_backend_rejected_at_construction():
    with pytest.raises(SecretConfigurationError):
        _construct(current_backend_id="othergcm")


def test_non_base64_key_material_raises_configuration_error(monkeypatch):
    monkeypatch.setenv("NM_SECRET_KEY_GEN2", "!!! not base64 !!!")
    with pytest.raises(SecretConfigurationError):
        EnvironmentKeyProvider().get_key("gen2")


def test_unconfigured_backend_id_raises_configuration_error(handler):
    envelope = "ENC[v1:othergcm:gen2:c29tZXBheWxvYWQ=]"
    with pytest.raises(SecretConfigurationError):
        handler.decrypt(envelope, name="db_password")


def test_wrong_length_key_material_raises_configuration_error(env_keys):
    handler = _construct(current_key_id=SHORT_KEY_ID)
    with pytest.raises(SecretConfigurationError):
        handler.encrypt("hunter2", name="db_password")


def test_backend_rejects_non_32_byte_key_from_provider():
    # The backend must guard against a defective provider, so AES-128 cannot slip
    # through under an aes256gcm envelope. This drives the backend directly with
    # a provider that returns 16 bytes, hitting the backend's own length check
    # rather than the environment provider's.
    backend = AES256GCMBackend(_ShortKeyProvider())
    with pytest.raises(SecretConfigurationError):
        backend.encrypt(b"plaintext", key_id="gen2", aad=b"aad")
    with pytest.raises(SecretConfigurationError):
        backend.decrypt("c29tZXBheWxvYWQ=", key_id="gen2", aad=b"aad")


def test_absent_key_material_raises_configuration_error(handler):
    envelope = "ENC[v1:aes256gcm:absent:c29tZXBheWxvYWQ=]"
    with pytest.raises(SecretConfigurationError):
        handler.decrypt(envelope, name="db_password")

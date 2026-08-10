"""Size boundaries."""

import pytest

from nm_secrets import SecretFormatError, SecretHandler
from nm_secrets import envelope as envelope_module
from nm_secrets.envelope import MAX_ENVELOPE_CHARS


class _OversizedBackend:
    """A conforming backend that returns a payload overflowing the envelope."""

    backend_id = "aes256gcm"

    def encrypt(self, plaintext: bytes, *, key_id: str, aad: bytes) -> str:
        return "A" * (MAX_ENVELOPE_CHARS + 1)

    def decrypt(self, payload: str, *, key_id: str, aad: bytes) -> bytes:  # pragma: no cover
        raise AssertionError("not called")


def test_max_plaintext_succeeds_and_envelope_under_limit(handler):
    plaintext = "a" * 65536  # 65536 ASCII bytes
    envelope = handler.encrypt(plaintext, name="db_password")
    assert len(envelope) < MAX_ENVELOPE_CHARS
    assert handler.decrypt(envelope, name="db_password") == plaintext


def test_one_byte_over_limit_fails(handler):
    with pytest.raises(SecretFormatError):
        handler.encrypt("a" * 65537, name="db_password")


def test_multibyte_under_char_limit_but_over_byte_limit_fails(handler):
    # 32769 two-byte characters is 65538 bytes: under 65536 characters, over the
    # 65536-byte limit.
    plaintext = "é" * 32769
    assert len(plaintext) < 65536
    assert len(plaintext.encode("utf-8")) > 65536
    with pytest.raises(SecretFormatError):
        handler.encrypt(plaintext, name="db_password")


def test_encrypt_rejects_oversized_assembled_envelope():
    # The generic layer must never emit an envelope it would reject on read, even
    # if a backend produces an over-limit payload.
    handler = SecretHandler(
        namespace="x", backends=[_OversizedBackend()], current_key_id="gen1"
    )
    with pytest.raises(SecretFormatError):
        handler.encrypt("hi", name="n")


def test_parse_rejects_over_length_envelope():
    # The length limit is enforced by parse() itself, before any wrapper syntax
    # is examined. An over-length value raises even though it is otherwise a
    # well-formed envelope shape.
    too_long = "ENC[v1:aes256gcm:key_1:" + "A" * (MAX_ENVELOPE_CHARS + 1) + "]"
    assert len(too_long) > MAX_ENVELOPE_CHARS
    with pytest.raises(SecretFormatError):
        envelope_module.parse(too_long)

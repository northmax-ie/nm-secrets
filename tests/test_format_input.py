"""Format and input handling."""

import base64

import pytest

from nm_secrets import SecretDecryptionError, SecretFormatError
from nm_secrets.context import build_aad

from .helpers import CURRENT_KEY_ID


def _payload_of(envelope: str) -> str:
    inner = envelope[len("ENC["):-1]
    return inner.split(":", 3)[3]


def _with_payload(payload: str) -> str:
    return f"ENC[v1:aes256gcm:{CURRENT_KEY_ID}:{payload}]"


def test_corrupt_ciphertext_fails(handler):
    envelope = handler.encrypt("hunter2", name="db_password")
    payload = _payload_of(envelope)
    # Flip an early payload character to another valid Base64 character, so the
    # value still decodes but authentication fails.
    idx = 20
    flipped = "A" if payload[idx] != "A" else "B"
    corrupted = payload[:idx] + flipped + payload[idx + 1:]
    with pytest.raises(SecretDecryptionError):
        handler.decrypt(_with_payload(corrupted), name="db_password")


def test_invalid_tag_fails(handler):
    envelope = handler.encrypt("hunter2", name="db_password")
    payload = _payload_of(envelope)
    # The tag is the final 16 bytes. Flip one tag byte in the decoded bytes and
    # re-encode, so the change cannot land only on discarded Base64 padding bits
    # (the failure mode of mutating the trailing Base64 character directly).
    raw = bytearray(base64.b64decode(payload, altchars=b"-_", validate=True))
    raw[-1] ^= 0x01
    corrupted = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(SecretDecryptionError):
        handler.decrypt(_with_payload(corrupted), name="db_password")


def test_invalid_base64_fails(handler):
    with pytest.raises(SecretFormatError):
        handler.decrypt(_with_payload("not*valid*base64*payload"), name="db_password")


def test_base64_non_alphabet_char_not_silently_discarded(handler):
    # A payload with a stray non-alphabet character that non-strict decoding
    # would drop before checking padding must be rejected.
    envelope = handler.encrypt("hunter2", name="db_password")
    payload = _payload_of(envelope)
    poisoned = payload[:10] + "@" + payload[10:]
    with pytest.raises(SecretFormatError):
        handler.decrypt(_with_payload(poisoned), name="db_password")


def test_truncated_payload_fails(handler):
    # Valid Base64 that decodes to fewer bytes than a nonce plus tag.
    with pytest.raises(SecretFormatError):
        handler.decrypt(_with_payload("c2hvcnQ="), name="db_password")


def test_plain_string_is_not_passed_through(handler):
    with pytest.raises(SecretFormatError):
        handler.decrypt("just a plain configuration value", name="db_password")


def test_invalid_utf8_after_decrypt_raises_format_error(handler, backend):
    # Drive the backend directly with non-UTF-8 bytes, using the AAD the handler
    # will reconstruct for this name, then decrypt through the handler.
    aad = build_aad("v1", "aes256gcm", CURRENT_KEY_ID, "enclave", "db_password")
    payload = backend.encrypt(b"\xff\xfe\xff\x00", key_id=CURRENT_KEY_ID, aad=aad)
    with pytest.raises(SecretFormatError):
        handler.decrypt(_with_payload(payload), name="db_password")

"""Fixed vectors, deterministic output structure, and disclosure hygiene."""

import base64
import traceback

from nm_secrets import (
    AES256GCMBackend,
    EnvironmentKeyProvider,
    SecretDecryptionError,
    SecretFormatError,
    SecretHandler,
)

from .synthetic_key_material import (
    VECTOR_ENVELOPE,
    VECTOR_NAME,
    VECTOR_PLAINTEXT,
)


def test_fixed_decryption_vector(handler):
    # The env_keys fixture installs the synthetic key under gen2, and the
    # handler is in namespace 'enclave'. The vector was produced with exactly
    # these parameters.
    assert handler.decrypt(VECTOR_ENVELOPE, name=VECTOR_NAME) == VECTOR_PLAINTEXT


def test_encryption_output_structure_with_fixed_nonce(handler, monkeypatch):
    fixed_nonce = b"0123456789ab"  # 12 bytes

    def fake_urandom(n):
        return (fixed_nonce * n)[:n]

    monkeypatch.setattr("os.urandom", fake_urandom)

    plaintext = "structured"
    envelope = handler.encrypt(plaintext, name="db_password")
    # Deterministic under a fixed nonce: same input, identical output. This is
    # the only way to fix encryption output; no API parameter supplies the nonce.
    assert handler.encrypt(plaintext, name="db_password") == envelope

    # Exact writer vector: pins the produced format byte for byte, not just its
    # shape, so a writer-format change cannot pass a permissive reader unnoticed.
    assert envelope == (
        "ENC[v1:aes256gcm:gen2:MDEyMzQ1Njc4OWFid96MXe3twae_C2KH_TMGdNX_fLahe9TqAC0=]"
    )

    payload = envelope[len("ENC[v1:aes256gcm:gen2:"):-1]
    raw = base64.b64decode(payload, altchars=b"-_", validate=True)
    assert raw[:12] == fixed_nonce
    assert len(raw) == 12 + len(plaintext.encode("utf-8")) + 16


def test_unsupported_version_message_omits_the_version(handler):
    # The version is untrusted, unbounded input; it must not reach the message
    # (and hence logs) verbatim.
    marker = "MARKER_9f2c_should_not_leak"
    try:
        handler.decrypt(f"ENC[v{marker}:aes256gcm:gen2:payload]", name="n")
    except SecretFormatError as exc:
        assert marker not in str(exc)
    else:
        raise AssertionError("expected SecretFormatError")


def test_exception_discloses_no_sensitive_input(monkeypatch, caplog):
    plaintext_marker = "PLAINTEXT_MARKER_do_not_leak"
    key_marker = b"KEYMARKER_" + b"0" * 22  # 32 bytes, recognisable prefix
    assert len(key_marker) == 32

    monkeypatch.setenv(
        "NM_SECRET_KEY_HYGIENE",
        base64.b64encode(key_marker).decode("ascii"),
    )
    handler = SecretHandler(
        namespace="enclave",
        backends=[AES256GCMBackend(EnvironmentKeyProvider())],
        current_backend_id="aes256gcm",
        current_key_id="hygiene",
    )

    envelope = handler.encrypt(plaintext_marker, name="db_password")
    payload = envelope[len("ENC[v1:aes256gcm:hygiene:"):-1]
    tampered_payload = ("A" if payload[15] != "A" else "B").join(
        (payload[:15], payload[16:])
    )
    tampered = f"ENC[v1:aes256gcm:hygiene:{tampered_payload}]"

    with caplog.at_level("DEBUG"):
        try:
            handler.decrypt(tampered, name="db_password")
        except SecretDecryptionError as exc:
            rendered = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            )
            haystack = str(exc) + rendered + caplog.text

            assert plaintext_marker not in haystack
            assert "KEYMARKER_" not in haystack
            assert payload not in haystack
            assert tampered_payload not in haystack

            # from None sets both of these; __context__ is deliberately not
            # asserted on.
            assert exc.__cause__ is None
            assert exc.__suppress_context__ is True
        else:
            raise AssertionError("expected SecretDecryptionError")

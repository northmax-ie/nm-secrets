"""The public handler: the str contract, size limits, and dispatch.

UTF-8 encodes plaintext and enforces the byte limit before any backend runs;
owns version support and backend dispatch. Callers never touch AESGCM objects,
nonces, tags, Base64, envelope parsing, or AAD serialisation.
"""

from collections.abc import Iterable

from . import envelope as _envelope
from .interfaces import SecretCipherBackend
from .context import build_aad
from .envelope import Envelope
from .exceptions import (
    SecretConfigurationError,
    SecretEncryptionError,
    SecretFormatError,
)

CURRENT_VERSION = "v1"
SUPPORTED_VERSIONS = frozenset({"v1"})
MAX_PLAINTEXT_BYTES = 65536


class SecretHandler:
    """Encrypts and decrypts values in the shared envelope format.

    Backends are keyed internally by their self-reported ``backend_id``, so the
    map key and the identifier stamped into an envelope cannot disagree.
    ``current_backend_id`` may be omitted when exactly one backend is registered.
    """

    def __init__(
        self,
        namespace: str,
        backends: Iterable[SecretCipherBackend],
        current_key_id: str,
        current_backend_id: str | None = None,
    ) -> None:
        by_id: dict[str, SecretCipherBackend] = {}
        for backend in backends:
            backend_id = backend.backend_id
            if not _envelope.is_valid_backend_id(backend_id):
                raise SecretConfigurationError(
                    f"backend reports invalid backend_id {backend_id!r}"
                ) from None
            if backend_id in by_id:
                raise SecretConfigurationError(
                    f"duplicate backend_id {backend_id!r}"
                ) from None
            by_id[backend_id] = backend

        if current_backend_id is None:
            if len(by_id) != 1:
                raise SecretConfigurationError(
                    "current_backend_id must be given unless exactly one backend "
                    f"is registered; {len(by_id)} are"
                ) from None
            current_backend_id = next(iter(by_id))

        if not _envelope.is_valid_key_id(current_key_id):
            raise SecretConfigurationError(
                f"invalid current_key_id {current_key_id!r}"
            ) from None
        if current_backend_id not in by_id:
            raise SecretConfigurationError(
                f"current_backend_id {current_backend_id!r} is not configured"
            ) from None

        self._namespace = namespace
        self._backends = by_id
        self._current_backend_id = current_backend_id
        self._current_key_id = current_key_id

    def _select_backend(self, backend_id: str) -> SecretCipherBackend:
        try:
            return self._backends[backend_id]
        except KeyError:
            raise SecretConfigurationError(
                f"backend_id {backend_id!r} is not configured"
            ) from None

    def encrypt(self, plaintext: str, name: str) -> str:
        """Encrypt under the current backend and key. ``name`` binds the value
        through the AAD and is not recoverable from the envelope."""
        encoded = plaintext.encode("utf-8")
        if len(encoded) > MAX_PLAINTEXT_BYTES:
            raise SecretFormatError("plaintext exceeds maximum size") from None

        backend = self._backends[self._current_backend_id]
        aad = build_aad(
            CURRENT_VERSION,
            self._current_backend_id,
            self._current_key_id,
            self._namespace,
            name,
        )
        payload = backend.encrypt(encoded, key_id=self._current_key_id, aad=aad)
        if not isinstance(payload, str):
            # A backend that returns non-str (for example bytes) would otherwise
            # be stringified into a malformed envelope.
            raise SecretEncryptionError("backend returned a non-string payload") from None
        envelope = f"ENC[{CURRENT_VERSION}:{self._current_backend_id}:{self._current_key_id}:{payload}]"
        if len(envelope) > _envelope.MAX_ENVELOPE_CHARS:
            # A backend produced a payload that overflows the envelope limit; the
            # handler must never emit a value it would itself reject on read.
            raise SecretFormatError("assembled envelope exceeds maximum length") from None
        return envelope

    def decrypt(self, envelope: str, name: str) -> str:
        """Decrypt ``envelope`` bound to ``name``. Rejects an unsupported version
        before dispatching."""
        parsed = self._parse_supported(envelope)
        backend = self._select_backend(parsed.backend_id)
        aad = build_aad(
            parsed.version,
            parsed.backend_id,
            parsed.key_id,
            self._namespace,
            name,
        )
        plaintext_bytes = backend.decrypt(parsed.payload, key_id=parsed.key_id, aad=aad)
        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise SecretFormatError("decrypted value is not valid UTF-8") from None

    def reencrypt(self, envelope: str, name: str) -> str:
        """Re-encrypt under the current backend and key. A single ``name``:
        renaming is a caller-managed two-name migration, and one name here
        prevents a decrypt/encrypt mismatch that would only surface on next read.
        """
        return self.encrypt(self.decrypt(envelope, name), name)

    def requires_reencryption(self, envelope: str) -> bool:
        """Whether the envelope's version, backend ID, or key ID differs from the
        handler's current values. Raises SecretFormatError on a syntactically
        invalid envelope; a valid envelope with an unsupported version returns
        True. Does not detect stale key material (for a remote backend, internal
        key-version rotation lives in the opaque payload)."""
        # Version discovery only: a newer package may write an envelope whose
        # internal structure is not v1, and a mere version mismatch is enough to
        # answer True without needing that structure to be readable.
        version = _envelope.discover_version(envelope)
        if version != CURRENT_VERSION:
            return True
        parsed = _envelope.parse(envelope)
        return (
            parsed.backend_id != self._current_backend_id
            or parsed.key_id != self._current_key_id
        )

    def _parse_supported(self, envelope: str) -> Envelope:
        # The message never echoes the version: it is untrusted, unbounded input
        # and must not reach logs verbatim.
        if _envelope.discover_version(envelope) not in SUPPORTED_VERSIONS:
            raise SecretFormatError("unsupported envelope version") from None
        return _envelope.parse(envelope)

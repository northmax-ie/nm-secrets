"""Envelope format v1: the wrapper around an opaque backend payload.

Owns wrapper syntax only; never imports from nm_secrets.backends. Grammar:
``ENC[<version>:<backend_id>:<key_id>:<payload>]``. Version discovery is frozen
permanently (``ENC[`` prefix, terminating ``]``, version up to the first ``:``);
the rest is frozen for v1 only.
"""

import re
from typing import NamedTuple

from .exceptions import SecretFormatError

MAX_ENVELOPE_CHARS = 90000
"""Fixed, not configurable: a configurable limit would let one application write
a value another refuses to read, breaking interoperability."""

_PREFIX = "ENC["
_TERMINATOR = "]"

# fullmatch, not match: with match a trailing ``\n`` slips past ``$`` (which
# matches before a final newline), admitting "gen2\n" into a frozen grammar.
_KEY_ID_RE = re.compile(r"[a-z0-9_]{1,64}")
_BACKEND_ID_RE = re.compile(r"[a-z0-9]{1,32}")


class Envelope(NamedTuple):
    """A parsed envelope; a named type, never a bare tuple."""

    version: str
    backend_id: str
    key_id: str
    payload: str


def discover_version(value: str) -> str:
    """Extract the format version using only the permanently frozen discovery
    rule: ``ENC[`` prefix, terminating ``]``, version up to the first ``:``.

    Works for any envelope version, including future ones whose internal
    structure differs from v1. Raises SecretFormatError if the value is not a
    discoverable envelope. Does not validate anything past the version.
    """
    if len(value) > MAX_ENVELOPE_CHARS:
        raise SecretFormatError("envelope exceeds maximum length") from None
    if not value.startswith(_PREFIX) or not value.endswith(_TERMINATOR):
        raise SecretFormatError("value is not an envelope") from None

    inner = value[len(_PREFIX):-len(_TERMINATOR)]
    version, sep, _rest = inner.partition(":")
    if not sep or not version:
        # No delimiter, or an empty version (``ENC[:...]``): malformed, not a
        # future version.
        raise SecretFormatError("envelope has no version") from None
    return version


def parse(value: str) -> Envelope:
    """Validate v1 wrapper syntax and return an Envelope. Does not check that the
    version is supported, but does require the v1 four-part structure and
    identifier grammar. For version discovery across other versions use
    ``discover_version``. Raises SecretFormatError on any violation."""
    if len(value) > MAX_ENVELOPE_CHARS:
        raise SecretFormatError("envelope exceeds maximum length") from None

    if not value.startswith(_PREFIX) or not value.endswith(_TERMINATOR):
        raise SecretFormatError("value is not an envelope") from None

    inner = value[len(_PREFIX):-len(_TERMINATOR)]

    # Split at most three times: the payload is kept whole and may contain ``:``
    # and ``]``. An unbounded split would silently require a colon-free payload.
    parts = inner.split(":", 3)
    if len(parts) != 4:
        raise SecretFormatError("envelope has too few components") from None

    version, backend_id, key_id, payload = parts

    if not _BACKEND_ID_RE.fullmatch(backend_id):
        raise SecretFormatError("invalid backend_id in envelope") from None
    if not _KEY_ID_RE.fullmatch(key_id):
        raise SecretFormatError("invalid key_id in envelope") from None

    return Envelope(version=version, backend_id=backend_id, key_id=key_id, payload=payload)


def is_valid_key_id(key_id: str) -> bool:
    """Whether ``key_id`` matches the v1 grammar. A non-string is not valid (and
    must not reach the regex, which would raise ``TypeError``)."""
    return isinstance(key_id, str) and _KEY_ID_RE.fullmatch(key_id) is not None


def is_valid_backend_id(backend_id: str) -> bool:
    """Whether ``backend_id`` matches the v1 grammar. A non-string is not valid."""
    return isinstance(backend_id, str) and _BACKEND_ID_RE.fullmatch(backend_id) is not None

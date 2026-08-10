"""nm-secrets: the shared at-rest encrypted-value format for NorthMax apps.

Import this package by symbol. Never alias it to ``secrets``, which is a stdlib
module already in use in consuming applications.
"""

from .backends.aes256gcm import AES256GCMBackend
from .envelope import Envelope
from .exceptions import (
    NmSecretsError,
    SecretConfigurationError,
    SecretDecryptionError,
    SecretEncryptionError,
    SecretFormatError,
)
from .handler import SecretHandler
from .interfaces import KeyProvider, SecretCipherBackend
from .providers.environment import EnvironmentKeyProvider

__all__ = [
    "AES256GCMBackend",
    "EnvironmentKeyProvider",
    "Envelope",
    "KeyProvider",
    "NmSecretsError",
    "SecretCipherBackend",
    "SecretConfigurationError",
    "SecretDecryptionError",
    "SecretEncryptionError",
    "SecretFormatError",
    "SecretHandler",
]

"""Exception hierarchy. Everything inherits from NmSecretsError.

No PayloadFormatError: a malformed payload is still a format problem. The
layer split governs docs, not this hierarchy.
"""


class NmSecretsError(Exception):
    """Base class for every error raised by nm-secrets."""


class SecretFormatError(NmSecretsError):
    """A value is not a well-formed, readable secret: not an envelope, malformed,
    unsupported version at an interpreting operation, a bad identifier, a size
    limit exceeded, a malformed payload, or invalid UTF-8 after a good decrypt.
    """


class SecretConfigurationError(NmSecretsError):
    """The handler or a backend is misconfigured: unknown or unconfigured backend
    or key ID, key material missing or the wrong length, or a bad configured id.
    """


class SecretDecryptionError(NmSecretsError):
    """Authentication failed: a wrong key or tampering, and nothing else."""


class SecretEncryptionError(NmSecretsError):
    """An unexpected backend failure during encryption, after input and config
    validation have passed. Never wraps a configuration or format error.
    """

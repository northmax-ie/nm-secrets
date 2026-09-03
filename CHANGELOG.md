# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Package semantic versioning applies to the package independently of the
envelope format version. A released envelope version is immutable, and support
for decrypting values written under it is never dropped silently; retiring a
released format requires a major release with migration guidance and a
documented security rationale.

## [0.1.0] - 2026-08-04

### Added

- Envelope format v1: `ENC[<version>:<backend_id>:<key_id>:<payload>]`. Version
  discovery is frozen permanently across all envelope versions; the v1 grammar
  is frozen for v1.
- `aes256gcm` backend: AES-256-GCM via `cryptography`, 12-byte `os.urandom`
  nonce per operation, 16-byte tag; payload is URL-safe Base64 of
  `nonce || ciphertext || tag`, padding retained.
- `EnvironmentKeyProvider` reading `NM_SECRET_KEY_<KEYID>`.
- Length-prefixed AAD binding version, backend ID, key ID, namespace and secret
  name.
- `SecretHandler` with `encrypt`, `decrypt`, `reencrypt` and
  `requires_reencryption`, a backend map, and the plaintext and envelope size
  limits.
- Exception hierarchy rooted at `NmSecretsError`.
- `docs/format-v1.md` (envelope layer) and `docs/backend-aes256gcm.md` (payload
  layer).
- Test suite with fixed decryption vectors.

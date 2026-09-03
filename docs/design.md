# nm-secrets design rationale

Why the architecture made the choices it did. What the contract is lives in the
normative specs ([format-v1.md](format-v1.md),
[backend-aes256gcm.md](backend-aes256gcm.md)); how to consume the library is in
[usage.md](usage.md).

## Why a library, not a function

The reason is the **stored format**. Several applications must produce values
that are mutually readable, rotatable, and reviewable once. The envelope, the key
ID, the backend ID, and the AAD binding all follow from that shared format.
Everything not implied by the format belongs to the calling application, which is
why the library stores nothing, reads no config, and knows nothing about any
particular application.

## Why AES-256-GCM rather than Fernet

Fernet is built from established cryptographic primitives and is not rejected
here because it is broken or discredited.

It is unsuitable here for two reasons:

1. **Decisive, functional.** Fernet has no associated-data mechanism, so binding
   ciphertext to a namespace and secret name is structurally impossible. That
   binding is the whole point of this library, so Fernet cannot do the job
   regardless of any other consideration.
2. **Secondary.** Fernet itself is not a NIST-specified construction, so there is
   no standard to put in front of an assessor; AES-GCM is specified in
   SP 800-38D.

Validated-module execution is an identical problem for both and does not
distinguish them.

## Why key providers sit behind local backends

A key provider resolves a key ID to raw key material. It belongs to a local
cipher backend, not to the handler, because a remote service that encrypts on
your behalf (Vault Transit, cloud KMS, an HSM-backed service) never exposes key
material and therefore has no provider at all. Placing the provider on the
handler would give the generic layer a concept that does not apply to every
backend. A service that encrypts on your behalf is a backend, not a provider.

## Cryptographic posture

No cryptographic primitive is implemented in this repository. The `aes256gcm`
backend routes cryptographic operations through `cryptography`'s `AESGCM`, and
nonce generation uses `os.urandom`. Its selected algorithm is AES-256-GCM
(NIST SP 800-38D).

**FIPS.** Using an approved algorithm is not the same as validated operation.
FIPS 140-3 validation is a property of the deployed cryptographic module, its
configuration, operational environment, and approved mode, not of this package.
There is a practical trap worth stating: `cryptography` ships statically linked
wheels for macOS, Windows, and Linux, so a host having a FIPS-configured OpenSSL
does not by itself place operations inside a validated module. Which FIPS requirement
applies, and the exact runtime, provider, and configuration needed to satisfy it,
is deployment-specific and out of scope for this library. This package makes no
validated-operation claim.

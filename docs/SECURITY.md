# mncs-crypto security model

No novel cryptography is designed here. The audited primitives are
RustCrypto `sha2 0.10.9` and `ed25519-dalek 2.2.0`, invoked through the
executor's capability grants; the native code owns composition,
typing, and verification only. This document states the actual
boundaries. Nothing below claims more than was verified.

## What is verified

- Known-answer vectors for every operation, pinned from FIPS 180-4,
  RFC 4231, RFC 5869, and RFC 8032, confirmed by independent oracles
  (OpenSSL-backed `hashlib`/`hmac`, `cryptography` 46.0.7) and by
  cross-backend agreement (21/21 cases, two documented restrictions).
- Tamper, wrong-key, malformed, boundary, and exhaustion cases return
  structured verdicts; authentication/signature failure is a value
  (`false`, status `1`), backend failure is an infrastructure outcome —
  never confused.
- The grant boundary: without `--grant-crypto`, effectful entries are
  `unsupported`; malformed shapes are refused purely before any host
  call.

## What is explicitly NOT claimed

- **Constant-time execution.** Tag comparison is ordinary native
  comparison. The toolchain provides no constant-time compare
  primitive and MNCS cannot guarantee timing behavior
  (`CRYPTO-PRESS-CT`). Do not use this for threat models that require
  timing resistance beyond what `ed25519-dalek` provides internally.
- **Secret memory erasure.** Byte arrays are copyable runtime values;
  no zeroization primitive exists and none is simulated
  (`CRYPTO-PRESS-MEM`). Secrets live as long as their owners keep them.
- **Production randomness.** There is no CSPRNG grant; `random.mncs`
  offers test entropy only (`CRYPTO-PRESS-RNG`). Generating real keys
  or nonces from this repository today is unsupported.
- **Side-channel resistance** of native code beyond the above.
- **Persistence safety.** Nothing here persists secrets. Private key
  material must never pass through generic Store paths; no helper here
  serializes secrets at all.

## Secret handling rules (enforced by construction)

- Secret types (`HmacKey`) have no hex, display, or logging projection
  anywhere in the repository. Public values do.
- Errors carry numeric codes and length facts only — never secret
  bytes. Decoders zero their entire output on any error.
- The test-entropy canary gate in `crypto_check.py` fails the run if
  fixed test patterns ever surface in result output.

## Out of scope by design

Unauthenticated encryption, signing (no secret crosses the grant
boundary), password hashing, key exchange, certificates, protocols,
secret storage, AEAD. Each needs a vetted backend grant or an owning
subsystem first; pressures are recorded, not silently worked around.

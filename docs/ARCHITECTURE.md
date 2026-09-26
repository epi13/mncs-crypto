# Architecture

## Layers

1. **Bit/byte primitives** — fixed-width integers, rotations, endian conversion, blocks and constant-time helpers.
2. **Conformance workloads** — established hashes/MACs/ciphers or arithmetic kernels selected for language pressure.
3. **Vectors** — authoritative known-answer and edge-case vectors.
4. **Memory contract** — secret-bearing buffers, explicit clearing and lifetime boundaries.
5. **Backend evidence** — optimized-code inspection, timing experiments and cross-target comparison.
6. **Regression harness** — reproducible compiler/backend conformance campaigns.

## First milestones

1. Fixed-width/bit-operation conformance corpus.
2. One established hash primitive against published vectors.
3. Constant-time helper/evidence experiments.
4. Zeroization/lifetime experiments.
5. SIMD/backend comparison and compiler-regression suite.

## Realization (2026-09-26)

The intent above is now implemented as native MNCS modules in
`mncs/crypto/`, verified by `scripts/crypto_check.py`:

- `types` — algorithm descriptors and semantic values; fixed sizes
  make key/signature misuse static.
- `buffer` — empty-safe view copies (language boundary documented in
  `LANGUAGE_PRESSURES.md` under CRYPTO-PRESS-EMPTY-VIEW).
- `encode` — hex for public values only; decoders zero output on error.
- `hash` — SHA-256 over `mncs.std.sha256` with chunked absorption
  (messages to 256 bytes) and the single round-constant table.
- `hmac` — RFC 2104 composition (keys to 256 bytes, pre-hashed past
  the block; messages to 192 bytes) with verdict verification.
- `hkdf` — RFC 5869 extract/expand (128-byte outputs, four blocks).
- `sig` — Ed25519 verification behind the executor grant; no signing
  key type exists because no secret crosses the boundary.
- `random` — deterministic test entropy; production CSPRNG is an
  explicit pressure (CRYPTO-PRESS-RNG), not a stub.

Ownership answers: Data/Store/Fabric/Forge/Signal/CLI/MCP gained no
crypto code in this campaign. Deliberately deferred (no backend or
owner yet): AEAD, signing, password hashing, key exchange, secret
storage, persistence of secrets.

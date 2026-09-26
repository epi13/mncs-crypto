# mncs-crypto

Canonical cryptographic abstraction for MNCS: typed values, explicit
effects, precise failure semantics, and authoritative verification —
over established primitives, never reinvented ones.

## What Crypto owns

Cryptographic semantics and safe typed interfaces:

- algorithm identities (`HashAlg`, `MacAlg`, `KdfAlg`, `SigAlg` — never
  bare strings);
- semantic value types (`Digest`, `HmacKey`, `Tag`, `ShortTag`,
  `PublicKey`, `Signature`) that make size and secrecy misuse
  statically impossible or structurally rejected;
- operation contracts (SHA-256, HMAC-SHA-256, HKDF-SHA-256, Ed25519
  verification) as standardized compositions;
- result/error semantics (`CryptoError` codes carry no secret bytes);
- hex projections for public values only (no text path exists for
  secret key material);
- deterministic test entropy with an explicit production boundary.

## What Crypto does not own

- Primitive implementation: SHA-256 compression lives in
  `mncs.std.sha256`; host-backed operations run through the executor's
  vetted backends (RustCrypto `sha2 0.10.9`, `ed25519-dalek 2.2.0`).
- Secret management, persistence, protocols, certificates, encoding
  libraries, orchestration. See `docs/ARCHITECTURE.md` for boundaries
  with Data, Store, Fabric, and Forge.
- Production randomness: the toolchain currently grants no OS CSPRNG,
  so this repository offers no production secret generation. Tests use
  injected `TestEntropy`. See `docs/SECURITY.md` and `CRYPTO-PRESS-RNG`.

## Layout

- `mncs/crypto/` — native modules: `types`, `buffer`, `encode`,
  `hash`, `hmac`, `hkdf`, `sig`, `random`.
- `tests/crypto/` — `mncs test` suites (41 cases). Long literals were
  machine-emitted by `scripts/mncs_bytes.py` from pinned hex, never
  hand-typed.
- `corpora/` — pinned experiment corpora, rebuilt by
  `scripts/build_crypto_corpora.py` and drift-gated by the checker.
- `scripts/crypto_check.py` — the enforcement boundary (below).

## Verification

`python3 scripts/crypto_check.py` gates, fail-closed:

1. corpora in sync with the pinned-vector generator;
2. every pin agrees with the independent host oracle (OpenSSL-backed
   `hashlib`/`hmac`, `cryptography` for Ed25519);
3. all six `mncs test` suites PASS (unknown is failure here);
4. every corpus case meets expectations with bit-exact returned values
   across all three backends (wasm, bytecode, cranelift), except two
   documented backend restrictions;
5. the sig corpus passes with `--grant-crypto` and fails closed
   without it (5 unsupported, 2 pure-shape refusals);
6. the test-entropy canary never appears in suite output.

Known-answer sources: FIPS 180-4 (SHA-256), RFC 4231 (HMAC cases
1–7 incl. truncation and long keys), RFC 5869 appendix A cases 1–3,
RFC 8032 section 7 tests 1–3. Pins were cross-checked against the RFC
texts, not only against the oracle.

## Pressures

Genuine toolchain gaps found by this work are recorded in
`docs/LANGUAGE_PRESSURES.md` with minimal reproducers — notably the
absence of a CSPRNG grant, of constant-time comparison, of secret
types, and two backend restrictions discovered during agreement runs.

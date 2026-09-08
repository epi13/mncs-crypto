# mncs-crypto

Machine-native cryptographic systems pressure laboratory for MNCS.

`mncs-crypto` uses established cryptographic primitives and published test vectors to pressure `mncs-language` on exact integer semantics, bit operations, constant-time behavior, memory handling, endian/alignment control, vectorization and compiler optimization guarantees.

It is initially a correctness and language-pressure project, not a request to invent novel cryptography.

## Initial scope

- byte/word and endian primitives
- hashes/MACs and selected established primitives as test workloads
- constant-time comparison and coding patterns
- standard/published test-vector harnesses
- memory zeroization and secret-lifetime experiments
- compiler/backend inspection for timing-sensitive code
- CPU/SIMD portability and conformance

## Repository layout

- `docs/ARCHITECTURE.md`
- `docs/rfcs/0001-foundation.md`
- `docs/LANGUAGE_PRESSURES.md`
- `AGENTS.md`

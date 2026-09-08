# Agent and contributor contract

- Prefer `mncs-language` for pressure implementations.
- Use established algorithms/specifications and authoritative test vectors; do not invent cryptographic schemes.
- Treat constant-time claims as properties requiring evidence, not source-level intuition.
- Never weaken or remove a conformance vector just to obtain a passing result.
- Keep experimental code clearly distinguished from production-ready cryptographic claims.
- Record language/compiler/backend gaps in `docs/LANGUAGE_PRESSURES.md` with minimal reproducers.
- Inspect optimized output where the compiler could invalidate timing or zeroization intent.

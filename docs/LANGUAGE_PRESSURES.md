# MNCS language pressure ledger

Record workload, current behavior, required semantic, reproducer, target/backend, workaround and verification.

## Initial pressure targets

- defined wrapping/checked integer arithmetic
- shift/rotate semantics for edge counts
- endian conversion and byte reinterpretation
- constant-time conditional/select primitives
- prevention/evidence of secret-dependent branches or memory access
- explicit zeroization that survives optimization
- alignment and packed/block data control
- aliasing/provenance rules for low-level buffers
- SIMD fixed-width operations
- inspectable compiler IR/assembly/PTX evidence
- cross-target conformance to published vectors

No constant-time or secure-erasure item is closed without backend-level evidence.

## CRYPTO-PRESS-RNG — no production CSPRNG grant (blocking for keygen)

The toolchain exposes no OS-CSPRNG intrinsic or `random` effect: `grep
-rn "getrandom\|OsRng\|thread_rng" crates/mncs-model/src crates/mncs-cli/src`
is empty, and `docs/language-capabilities.json` lists no randomness
capability. `mncs.crypto.random` therefore offers test entropy only.
Production key/nonce/salt generation is unrealizable in-repo.

Minimal probe: any `mncs` program needing 32 unpredictable bytes has no
intrinsic to call; `mncs.core.random` is a documented-transparent LCG.

## CRYPTO-PRESS-CT — no constant-time comparison primitive (non-blocking)

No `constant_time_equals` (or similar) exists in std/core or as an
intrinsic, so `hmac_verify` uses ordinary element-wise comparison with
an honest documented boundary. A vetted-backend comparison entry would
let the semantic API request secure verification without claiming
arbitrary MNCS code executes constant-time.

## CRYPTO-PRESS-SECRET — no secret/non-display type (non-blocking)

The language has no `secret` qualifier, opaque-bytes, or display
restriction: secrecy in `mncs-crypto` is enforced by API absence (no
projection functions for secret types), which works but is convention,
not a type guarantee. A value-level secret marker would make leakage
structurally impossible rather than merely unimplemented.

## CRYPTO-PRESS-EMPTY-VIEW — indexing an empty view traps (workaround shipped)

Indexing a runtime-empty view traps (`sequence index out of bounds`)
even under `select`, because index evaluation is not suppressed by the
guard. All crypto constructions route through `mncs.crypto.buffer`
copies that branch on `view.len` first. Additionally, fixed-array
indices must be select-narrowed *variables* (`let ii = select(i < N, i,
0); a[ii]`); the same index wrapped in `select` at the use site is
refused with `statically established sequence bounds were violated`.

Minimal reproducer (both fail before the workaround):
`sha256` over `[]` (empty view index); `stretch` over `[byte; 128]`
with a raw `fixed[i]` for `i` in `0..256`.

## CRYPTO-PRESS-MEM — no zeroization primitive (non-blocking)

No `zeroize`, pinned-buffer, or explicit-destruction facility exists
for byte arrays, so no erasure is claimed or simulated. If secret
lifetimes need enforcement, the runtime must grow a real primitive
first; ceremonial clearing would be false assurance.

## CRYPTO-PRESS-GRANT — capability grants realized on one backend (documented)

Only `mncs-research-bytecode` realizes the `ed25519_verify` host
grant; wasm and cranelift stub capability-needing closures at
per-entrypoint admission (`resolve_entry_export` → `Unsupported`, by
design). Agreement corpora therefore restrict sig cases to bytecode
with oracle backing. Extending grant realization to all backends (or
documenting the capability matrix) is toolchain work.

## CRYPTO-PRESS-ARENA — cranelift arena exhaustion on small inputs (open)

`hkdf-a1-block1` (45 argument bytes) deterministically fails on
`mncs-cranelift` with `MNCS_RSRC_EXHAUSTED cranelift JIT canonical
arena exhausted` (16MB), while the 22-byte shape passes and
bytecode/wasm agree on the value.

Reproducer:
`mncs experiment run mncs/crypto/hkdf.mncs --backend mncs-cranelift
--corpus corpora/crypto-hkdf-corpus.json` (unrestricted) — or the
minimal two-case corpus pairing 13+22+10-byte inputs against 0+22+0.
The corpus restricts this case to wasm+bytecode pending a backend fix.

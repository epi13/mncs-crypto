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

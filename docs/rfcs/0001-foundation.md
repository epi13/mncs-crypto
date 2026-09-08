# RFC 0001: Cryptographic pressure foundation

Status: Draft

## Principles

- The project pressures language/compiler semantics using established cryptographic workloads.
- Integer overflow, shifts, rotations, endian conversion and aliasing have explicit behavior.
- Constant-time behavior is a compiler/backend contract that requires verification.
- Secret-bearing memory should have explicit lifetime and clearing semantics where possible.
- Authoritative known-answer vectors are primary correctness evidence.
- Experimental implementations are not automatically suitable for production security use.

## Pressure objectives

Fixed-width integer semantics, wrapping/checked arithmetic, rotations, bit slicing, constant-time selection/comparison, optimizer barriers/contracts, zeroization, alignment, endian APIs, SIMD, memory aliasing, unsafe/low-level escape hatches and inspectable generated code.

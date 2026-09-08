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

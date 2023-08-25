# Halo2 keccak256

This repository contains a halo2 circuit for creating a proof of keccakf evaluations on multiple inputs. It uses only custom gates with no lookups or copy constraints.

The circuit is based on the [`keccak_stark`](https://github.com/mir-protocol/plonky2/blob/a0b2b489922b6b3e03116bf78cff323cc579ddd4/evm/src/keccak/keccak_stark.rs) implementation from Plonky2/Starky.

## Usage

```bash
cargo t -r -- --nocapture 
```

## Benchmarking

```bash
cargo t -r -- --nocapture bench_keccak 
```

## Profiling

```bash
sudo --preserve-env cargo flamegraph  --unit-test -- bench_keccak
```

Single threaded:

```bash
RAYON_NUM_THREADS=1 sudo --preserve-env cargo flamegraph  --unit-test -- bench_keccak
```

## Using different halo2 backends

The circuit can be compiled with three different backends

- [`axiom-backend`](https://github.com/axiom-crypto/halo2)
- [`pse-backend`](https://github.com/privacy-scaling-explorations/halo2)
- [`zcash-backend`](https://github.com/zcash/halo2)

Switch between each of the backends by running:

```bash
cargo t -r --no-default-features --features zcash-backend -- --nocapture
```
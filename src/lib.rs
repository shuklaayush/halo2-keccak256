mod columns;
mod logic;

use ff::{PrimeField, PrimeFieldBits};
use halo2_proofs::{arithmetic::Field, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

use columns::{reg_a, reg_a_prime, reg_c, reg_c_prime, reg_preimage, reg_step};
use logic::{xor, xor3_gen};
// use columns::{NUM_COLUMNS};

/// Number of rounds in a Keccak permutation.
// pub(crate) const NUM_ROUNDS: usize = 24;
pub(crate) const NUM_ROUNDS: usize = 2;

/// Number of 64-bit elements in the Keccak permutation input.
pub(crate) const NUM_INPUTS: usize = 25;

const NUM_COLUMNS: usize = 2292;

#[derive(Debug, Clone)]
struct KeccakConfig {
    pub cols: [Column<Advice>; NUM_COLUMNS],
    // TODO: There's redundancy here, but it's not clear how to remove it.
    //       halo2 selector type is very restrictive.
    pub selector: Selector,
    pub selector_first: Selector,
    pub selector_last: Selector,
    pub selector_not_last: Selector,

    pub instance: Column<Instance>,
    // pub constant: Column<Fixed>,
}

#[derive(Debug, Clone)]
struct KeccakChip<F: PrimeFieldBits> {
    config: KeccakConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Copy, Debug)]
pub struct PubValue<V> {
    pub inner: Option<V>,
}

impl<F: PrimeFieldBits> KeccakChip<F> {
    pub fn construct(config: KeccakConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> KeccakConfig {
        // Create columns

        let selector = meta.selector();
        let selector_first = meta.selector();
        let selector_last = meta.selector();
        let selector_not_last = meta.selector();

        let instance = meta.instance_column();
        // let constant = meta.fixed_column();

        meta.enable_equality(instance);
        // meta.enable_constant(constant);

        let cols: [Column<Advice>; NUM_COLUMNS] = (0..NUM_COLUMNS)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Assign constraints

        // First round flag
        // TODO: Maybe use copy constraint instead of gate and selector
        meta.create_gate("first_round_flag", |meta| {
            let s_first = meta.query_selector(selector_first);
            let first_round_flag = meta.query_advice(cols[reg_step(0)], Rotation::cur());
            vec![s_first * (first_round_flag - Expression::Constant(F::ONE))]
        });

        // Round flags
        for i in 0..NUM_ROUNDS {
            // To initialize the first round flag, we need to set it to 1
            meta.enable_equality(cols[reg_step(i)]);

            meta.create_gate("round_flags", |meta| {
                let s_not_last = meta.query_selector(selector_not_last);
                let current_round_flag = meta.query_advice(cols[reg_step(i)], Rotation::cur());
                let next_round_flag =
                    meta.query_advice(cols[reg_step((i + 1) % NUM_ROUNDS)], Rotation::next());
                vec![s_not_last * (next_round_flag - current_round_flag)]
            });
        }

        // Preimages
        for x in 0..5 {
            for y in 0..5 {
                // To initialize the first preimage, we need to set it to the input
                meta.enable_equality(cols[reg_preimage(x, y)]);

                meta.create_gate("preimage", |meta| {
                    let s_not_last = meta.query_selector(selector_not_last);
                    let preimage = reg_preimage(x, y);
                    let diff = meta.query_advice(cols[preimage], Rotation::cur())
                        - meta.query_advice(cols[preimage], Rotation::next());
                    vec![s_not_last * diff]
                });
            }
        }

        // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
        for x in 0..5 {
            for z in 0..64 {
                meta.create_gate("c_prime", |meta| {
                    let s = meta.query_selector(selector);
                    let xor = xor3_gen(
                        meta.query_advice(cols[reg_c(x, z)], Rotation::cur()),
                        meta.query_advice(cols[reg_c((x + 4) % 5, z)], Rotation::cur()),
                        meta.query_advice(cols[reg_c((x + 1) % 5, (z + 63) % 64)], Rotation::cur()),
                    );
                    let c_prime = meta.query_advice(cols[reg_c_prime(x, z)], Rotation::cur());
                    vec![s * (c_prime - xor)]
                });
            }
        }

        // Check that the input limbs are consistent with A' and D.
        // A[x, y, z] = xor(A'[x, y, z], D[x, y, z])
        //            = xor(A'[x, y, z], C[x - 1, z], C[x + 1, z - 1])
        //            = xor(A'[x, y, z], C[x, z], C'[x, z]).
        // The last step is valid based on the identity we checked above.
        // It isn't required, but makes this check a bit cleaner.
        for x in 0..5 {
            for y in 0..5 {
                meta.create_gate("a", |meta| {
                    let s = meta.query_selector(selector);
                    let a = meta.query_advice(cols[reg_a(x, y)], Rotation::cur());
                    let mut get_bit = |z| {
                        let a_prime =
                            meta.query_advice(cols[reg_a_prime(x, y, z)], Rotation::cur());
                        let c = meta.query_advice(cols[reg_c(x, z)], Rotation::cur());
                        let c_prime = meta.query_advice(cols[reg_c_prime(x, z)], Rotation::cur());
                        xor3_gen(a_prime, c, c_prime)
                    };
                    let computed = (0..64).rev().fold(Expression::Constant(F::ZERO), |acc, z| {
                        Expression::Constant(F::from(2)) * acc + get_bit(z)
                    });
                    vec![s * (a - computed)]
                });
            }
        }

        // Copying A'' to A for next round
        // TODO: Replace with actual columns
        for x in 0..5 {
            for y in 0..5 {
                // To initialize the first A, we need to set it to the input
                meta.enable_equality(cols[reg_a(x, y)]);

                meta.create_gate("a", |meta| {
                    let s_not_last = meta.query_selector(selector_not_last);
                    let a = reg_a(x, y);
                    let diff = meta.query_advice(cols[a], Rotation::cur())
                        - meta.query_advice(cols[a], Rotation::next());
                    vec![s_not_last * diff]
                });
            }
        }

        KeccakConfig {
            cols,
            selector,
            selector_first,
            selector_last,
            selector_not_last,
            instance,
            // constant,
        }
    }

    pub fn assign(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "keccak table",
            |mut region| {
                // Store values in local row
                let mut row: [F; NUM_COLUMNS] = [F::ZERO; NUM_COLUMNS];

                // Enable selectors
                self.config.selector_first.enable(&mut region, 0)?;
                self.config
                    .selector_last
                    .enable(&mut region, NUM_ROUNDS - 1)?;

                // Populate the preimage for first row.
                for x in 0..5 {
                    for y in 0..5 {
                        let preimage = reg_preimage(x, y);
                        let cell = region.assign_advice_from_instance(
                            || "preimage",
                            self.config.instance,
                            y * 5 + x,
                            self.config.cols[preimage],
                            0,
                        )?;
                        let value: PubValue<F> =
                            unsafe { std::mem::transmute_copy(&cell.value().copied()) };
                        if let Some(v) = value.inner {
                            row[preimage] = v;
                        }
                    }
                }

                // Populate A for first row.
                for x in 0..5 {
                    for y in 0..5 {
                        let a = reg_a(x, y);
                        region.assign_advice_from_instance(
                            || "a",
                            self.config.instance,
                            y * 5 + x,
                            self.config.cols[a],
                            0,
                        )?;
                        row[a] = row[reg_preimage(x, y)];
                    }
                }

                // Assign remaining rows
                for round in 0..NUM_ROUNDS {
                    self.config.selector.enable(&mut region, round)?;

                    if round < NUM_ROUNDS - 1 {
                        // Enable selector
                        self.config.selector_not_last.enable(&mut region, round)?;
                    }

                    if round > 0 {
                        // Assign preimage
                        for x in 0..5 {
                            for y in 0..5 {
                                let preimage = reg_preimage(x, y);
                                region.assign_advice(
                                    || "preimage",
                                    self.config.cols[preimage],
                                    round,
                                    || Value::known(row[preimage]),
                                )?;
                            }
                        }

                        // Assign A
                        // TODO: Change cur column to A''
                        for x in 0..5 {
                            for y in 0..5 {
                                let a = reg_a(x, y);
                                region.assign_advice(
                                    || "a",
                                    self.config.cols[a],
                                    round,
                                    || Value::known(row[a]),
                                )?;
                                row[a] = row[a];
                            }
                        }
                    }

                    // Assign round flags
                    for i in 0..NUM_ROUNDS {
                        let val = if i == round { F::ONE } else { F::ZERO };
                        region.assign_advice(
                            || "advice",
                            self.config.cols[reg_step(i)],
                            round,
                            || Value::known(val),
                        )?;
                        row[reg_step(i)] = val;
                    }

                    // Populate C[x] = xor(A[x, 0], A[x, 1], A[x, 2], A[x, 3], A[x, 4]).
                    for x in 0..5 {
                        for z in 0..64 {
                            let xor = xor(&(0..5)
                                .map(|i| {
                                    let ai = row[reg_a(x, i)];
                                    let bits = ai.to_le_bits();

                                    F::from(bits[z] as u64)
                                })
                                .collect::<Vec<_>>());
                            region.assign_advice(
                                || "c",
                                self.config.cols[reg_c(x, z)],
                                round,
                                || Value::known(xor),
                            )?;
                            row[reg_c(x, z)] = xor;
                        }
                    }

                    // Populate C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
                    for x in 0..5 {
                        for z in 0..64 {
                            let xor = xor(&[
                                row[reg_c(x, z)],
                                row[reg_c((x + 4) % 5, z)],
                                row[reg_c((x + 1) % 5, (z + 63) % 64)],
                            ]);
                            region.assign_advice(
                                || "c_prime",
                                self.config.cols[reg_c_prime(x, z)],
                                round,
                                || Value::known(xor),
                            )?;
                            row[reg_c_prime(x, z)] = xor;
                        }
                    }

                    // Populate A'. To avoid shifting indices, we rewrite
                    //     A'[x, y, z] = xor(A[x, y, z], C[x - 1, z], C[x + 1, z - 1])
                    // as
                    //     A'[x, y, z] = xor(A[x, y, z], C[x, z], C'[x, z]).
                    for x in 0..5 {
                        for y in 0..5 {
                            for z in 0..64 {
                                let a_bit = F::from(row[reg_a(x, y)].to_le_bits()[z] as u64);
                                let xor = xor(&[a_bit, row[reg_c(x, z)], row[reg_c_prime(x, z)]]);
                                region.assign_advice(
                                    || "a_prime",
                                    self.config.cols[reg_a_prime(x, y, z)],
                                    round,
                                    || Value::known(xor),
                                )?;
                                row[reg_a_prime(x, y, z)] = xor;
                            }
                        }
                    }
                }
                Ok(())
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}

#[derive(Default)]
struct KeccakCircuit<F>(PhantomData<F>);

impl<F: PrimeFieldBits> Circuit<F> for KeccakCircuit<F> {
    type Config = KeccakConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        KeccakChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = KeccakChip::construct(config);

        let out_cell = chip.assign(layouter.namespace(|| "table"))?;

        // chip.expose_public(layouter.namespace(|| "out"), &out_cell, NUM_INPUTS + 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    use std::marker::PhantomData;

    #[test]
    fn keccak_example1() {
        let k = 6;

        // let a = Fp::from(1); // F[0]
        // let out = Fp::from(55); // F[9]

        let circuit = KeccakCircuit(PhantomData);

        let input: [u64; NUM_INPUTS] = rand::random();
        let public_input = input.map(|x| Fp::from(x)).to_vec();

        // println!("public_input: {:?}", public_input);

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();

        // public_input[2] += Fp::one();
        // let _prover = MockProver::run(k, &circuit, vec![public_input]).unwrap();
        // uncomment the following line and the assert will fail
        // _prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_keccak1() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("keccak-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Keccak Layout", ("sans-serif", 60)).unwrap();

        let circuit = KeccakCircuit::<Fp>(PhantomData);
        halo2_proofs::dev::CircuitLayout::default()
            .render(5, &circuit, &root)
            .unwrap();
    }
}

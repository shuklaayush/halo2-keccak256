mod columns;
mod constants;
mod logic;

use ff::PrimeFieldBits;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

use columns::{
    reg_a, reg_a_prime, reg_a_prime_prime, reg_a_prime_prime_0_0_bit, reg_a_prime_prime_prime,
    reg_b, reg_c, reg_c_prime, reg_output, reg_preimage, reg_step, NUM_COLUMNS,
};
use constants::{rc_value, rc_value_bit};
use logic::{andn, andn_gen, xor, xor3_gen, xor_gen};
// use columns::{NUM_COLUMNS};

/// Number of rounds in a Keccak permutation.
// pub(crate) const NUM_ROUNDS: usize = 24;
pub(crate) const NUM_ROUNDS: usize = 24;

/// Number of 64-bit elements in the Keccak permutation input.
pub(crate) const NUM_INPUTS: usize = 25;

#[derive(Debug, Clone)]
struct KeccakConfig {
    pub cols: [Column<Advice>; NUM_COLUMNS],
    // TODO: There's redundancy here, but it's not clear how to remove it.
    //       halo2 selector type is very restrictive.
    pub selector: Selector,
    pub selector_first: Selector,
    pub selector_last: Selector,
    pub selector_not_last: Selector,

    pub instance_input: Column<Instance>,
    pub instance_output: Column<Instance>,
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

        let instance_input = meta.instance_column();
        let instance_output = meta.instance_column();

        let cols: [Column<Advice>; NUM_COLUMNS] = (0..NUM_COLUMNS)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Assign constraints

        // First round flag
        meta.create_gate("first_round_flag", |meta| {
            let s_first = meta.query_selector(selector_first);

            let first_round_flag = meta.query_advice(cols[reg_step(0)], Rotation::cur());
            vec![s_first * (first_round_flag - Expression::Constant(F::ONE))]
        });

        // Round flags
        for i in 0..NUM_ROUNDS {
            // To initialize the first round flag, we need to set it to 1
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
                // meta.create_gate("preimage first", |meta| {
                //     let s_first = meta.query_selector(selector_first);

                //     let preimage = reg_preimage(x, y);
                //     let input = meta.query_advice(cols[preimage], Rotation::cur());
                //     vec![
                //         s_first
                //             * (input
                //                 - meta
                //                     .query_instance(instance_input, Rotation((y * 5 + x) as i32))),
                //     ]
                // });

                // Copy remaining preimages
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

        // TODO: How do the constraints match with what's written below?
        // xor_{i=0}^4 A'[x, i, z] = C'[x, z], so for each x, z,
        // diff * (diff - 2) * (diff - 4) = 0, where
        // diff = sum_{i=0}^4 A'[x, i, z] - C'[x, z]
        for x in 0..5 {
            for z in 0..64 {
                meta.create_gate("a_prime", |meta| {
                    let s = meta.query_selector(selector);

                    let sum = (0..5).fold(Expression::Constant(F::ZERO), |acc, i| {
                        acc + meta.query_advice(cols[reg_a_prime(x, i, z)], Rotation::cur())
                    });
                    let c_prime = meta.query_advice(cols[reg_c_prime(x, z)], Rotation::cur());
                    let diff = sum - c_prime;
                    vec![
                        s * diff.clone()
                            * (diff.clone() - Expression::Constant(F::from(2)))
                            * (diff - Expression::Constant(F::from(4))),
                    ]
                });
            }
        }

        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
        for x in 0..5 {
            for y in 0..5 {
                meta.create_gate("a_prime_prime", |meta| {
                    let s = meta.query_selector(selector);

                    let a_prime_prime =
                        meta.query_advice(cols[reg_a_prime_prime(x, y)], Rotation::cur());
                    let mut get_bit = |z| {
                        xor_gen(
                            meta.query_advice(cols[reg_b(x, y, z)], Rotation::cur()),
                            andn_gen(
                                meta.query_advice(cols[reg_b((x + 1) % 5, y, z)], Rotation::cur()),
                                meta.query_advice(cols[reg_b((x + 2) % 5, y, z)], Rotation::cur()),
                            ),
                        )
                    };

                    let computed = (0..64).rev().fold(Expression::Constant(F::ZERO), |acc, z| {
                        Expression::Constant(F::from(2)) * acc + get_bit(z)
                    });

                    vec![s * (a_prime_prime - computed)]
                });
            }
        }

        // A'''[0, 0] = A''[0, 0] as bits
        meta.create_gate("a_prime_prime_0_0", |meta| {
            let s = meta.query_selector(selector);

            let a_prime_prime_0_0 =
                meta.query_advice(cols[reg_a_prime_prime(0, 0)], Rotation::cur());
            let mut get_bit =
                |i| meta.query_advice(cols[reg_a_prime_prime_0_0_bit(i)], Rotation::cur());

            let computed = (0..64).rev().fold(Expression::Constant(F::ZERO), |acc, i| {
                Expression::Constant(F::from(2)) * acc + get_bit(i)
            });

            vec![s * (a_prime_prime_0_0 - computed)]
        });

        // A'''[0, 0] = A''[0, 0] XOR RC
        // TODO: Maybe use fixed column for RC
        meta.create_gate("a_prime_prime_prime_0_0", |meta| {
            let s = meta.query_selector(selector);

            let a_prime_prime_prime_0_0 =
                meta.query_advice(cols[reg_a_prime_prime_prime(0, 0)], Rotation::cur());
            let mut get_xored_bit = |i| {
                let rc_bit_i = (0..NUM_ROUNDS).fold(Expression::Constant(F::ZERO), |acc, r| {
                    let this_round = meta.query_advice(cols[reg_step(r)], Rotation::cur());
                    let this_round_constant =
                        Expression::Constant(F::from(rc_value_bit(r, i) as u64));
                    acc + this_round * this_round_constant
                });

                xor_gen(
                    meta.query_advice(cols[reg_a_prime_prime_0_0_bit(i)], Rotation::cur()),
                    rc_bit_i,
                )
            };

            let computed = (0..64).rev().fold(Expression::Constant(F::ZERO), |acc, z| {
                Expression::Constant(F::from(2)) * acc + get_xored_bit(z)
            });

            vec![s * (a_prime_prime_prime_0_0 - computed)]
        });

        // Round input A
        for x in 0..5 {
            for y in 0..5 {
                // To initialize the first A, we need to set it to the input
                // meta.create_gate("a first", |meta| {
                //     let s_first = meta.query_selector(selector_first);

                //     let a = reg_a(x, y);
                //     let input = meta.query_advice(cols[a], Rotation::cur());
                //     vec![
                //         s_first
                //             * (input
                //                 - meta
                //                     .query_instance(instance_input, Rotation((y * 5 + x) as i32))),
                //     ]
                // });

                // Copying A'' to A for next round
                meta.create_gate("a", |meta| {
                    let s_not_last = meta.query_selector(selector_not_last);

                    let output =
                        meta.query_advice(cols[reg_a_prime_prime_prime(x, y)], Rotation::cur());
                    let input = meta.query_advice(cols[reg_a(x, y)], Rotation::next());

                    vec![s_not_last * (output - input)]
                });
            }

            // Output
            // for i in 0..NUM_INPUTS {
            //     meta.create_gate("output", |meta| {
            //         let s_last = meta.query_selector(selector_last);

            //         let output = meta.query_advice(cols[reg_output(i)], Rotation::cur());
            //         let expected = meta.query_instance(instance_output, Rotation(i as i32));
            //         vec![s_last * (output - expected)]
            //     });
            // }
        }

        KeccakConfig {
            cols,
            selector,
            selector_first,
            selector_last,
            selector_not_last,
            instance_input,
            instance_output,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        input: [F; NUM_INPUTS],
    ) -> Result<(), Error> {
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

                // Assign remaining rows
                for round in 0..NUM_ROUNDS {
                    self.config.selector.enable(&mut region, round)?;

                    if round < NUM_ROUNDS - 1 {
                        // Enable selector
                        self.config.selector_not_last.enable(&mut region, round)?;
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

                    if round == 0 {
                        // Populate A for first row.
                        for x in 0..5 {
                            for y in 0..5 {
                                let a = reg_a(x, y);
                                region.assign_advice(
                                    || "preimage",
                                    self.config.cols[a],
                                    0,
                                    || Value::known(input[y * 5 + x]),
                                )?;
                                row[a] = input[y * 5 + x];
                            }
                        }
                    } else {
                        // Assign A
                        for x in 0..5 {
                            for y in 0..5 {
                                let input = reg_a(x, y);
                                let output = reg_a_prime_prime_prime(x, y);
                                region.assign_advice(
                                    || "a",
                                    self.config.cols[input],
                                    round,
                                    || Value::known(row[output]),
                                )?;
                                row[input] = row[output];
                            }
                        }
                    }

                    // Populate the preimage for each row.
                    for x in 0..5 {
                        for y in 0..5 {
                            let preimage = reg_preimage(x, y);
                            let cell = region.assign_advice(
                                || "preimage",
                                self.config.cols[preimage],
                                0,
                                || Value::known(input[y * 5 + x]),
                            )?;
                            row[preimage] = input[y * 5 + x];
                        }
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

                    // Populate A''.
                    // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
                    for x in 0..5 {
                        for y in 0..5 {
                            let get_bit = |z| {
                                xor(&[
                                    row[reg_b(x, y, z)],
                                    andn(
                                        row[reg_b((x + 1) % 5, y, z)],
                                        row[reg_b((x + 2) % 5, y, z)],
                                    ),
                                ])
                            };

                            let val = (0..64)
                                .rev()
                                .fold(F::ZERO, |acc, z| F::from(2) * acc + get_bit(z));

                            region.assign_advice(
                                || "a_prime_prime",
                                self.config.cols[reg_a_prime_prime(x, y)],
                                round,
                                || Value::known(val),
                            )?;
                            row[reg_a_prime_prime(x, y)] = val;
                        }
                    }

                    // For the XOR, we split A''[0, 0] to bits.
                    let a_prime_prime_0_0_bits = row[reg_a_prime_prime(0, 0)].to_le_bits();

                    for i in 0..64 {
                        let val = F::from(a_prime_prime_0_0_bits[i] as u64);
                        region.assign_advice(
                            || "a_prime_prime_0_0",
                            self.config.cols[reg_a_prime_prime_0_0_bit(i)],
                            round,
                            || Value::known(val),
                        )?;
                        row[reg_a_prime_prime_0_0_bit(i)] = val;
                    }

                    // A''[0, 0] is additionally xor'd with RC.
                    let val = F::from(
                        a_prime_prime_0_0_bits
                            .iter()
                            .rev()
                            .fold(0u64, |acc, b| (acc << 1) + (*b as u64))
                            ^ rc_value(round),
                    );
                    region.assign_advice(
                        || "a_prime_prime_prime_0_0",
                        self.config.cols[reg_a_prime_prime_prime(0, 0)],
                        round,
                        || Value::known(val),
                    )?;
                    row[reg_a_prime_prime_prime(0, 0)] = val;
                }

                Ok(())
            },
        )
    }
}

#[derive(Default)]
struct KeccakCircuit<F> {
    input: [F; NUM_INPUTS],
    _marker: PhantomData<F>,
}

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

        chip.assign(layouter.namespace(|| "table"), self.input)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use std::marker::PhantomData;
    use tiny_keccak::keccakf;

    use ark_std::{end_timer, start_timer};
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use rand_core::OsRng;

    #[test]
    fn test_keccak_correctness() {
        let k = 6;

        let input: [u64; NUM_INPUTS] = rand::random();
        let expected = {
            let mut state = input;
            keccakf(&mut state);
            state
        };
        let circuit = KeccakCircuit {
            input: input.map(|x| Fr::from(x)),
            _marker: PhantomData,
        };

        let public_inputs = vec![
            input.map(|x| Fr::from(x)).to_vec(),
            expected.map(|x| Fr::from(x)).to_vec(),
        ];

        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_keccak_proof() {
        let k = 6;

        // let input: [u64; NUM_INPUTS] = rand::random();
        let input = [0u64; NUM_INPUTS];
        let expected = {
            let mut state = input;
            keccakf(&mut state);
            state
        };

        let circuit = KeccakCircuit {
            input: input.map(|x| Fr::from(x)),
            _marker: PhantomData,
        };

        let public_inputs = vec![
            input.map(|x| Fr::from(x)).to_vec(),
            expected.map(|x| Fr::from(x)).to_vec(),
        ];
        let instance = public_inputs
            .iter()
            .map(|v| v.as_slice())
            .collect::<Vec<_>>();

        // Generate proof
        let srs_params = ParamsKZG::<Bn256>::setup(k, ChaCha20Rng::from_seed(Default::default()));
        let mut rng = OsRng;

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&srs_params, &circuit).unwrap();
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&srs_params, vk, &circuit).unwrap();
        end_timer!(pk_time);

        let proof_time = start_timer!(|| "Proving time");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(
            &srs_params,
            &pk,
            &[circuit],
            &[&instance.as_slice()],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = proof.len();

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = srs_params.verifier_params();
        let strategy = SingleStrategy::new(&srs_params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            verifier_params,
            pk.get_vk(),
            strategy,
            &[&instance.as_slice()],
            &mut transcript,
        )
        .unwrap();
        end_timer!(verify_time);

        println!("proof_size: {} bytes", proof_size);
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_keccak() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("keccak-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Keccak Layout", ("sans-serif", 60)).unwrap();

        let circuit = KeccakCircuit {
            input: [Fr::ZERO; NUM_INPUTS],
            _marker: PhantomData,
        };

        halo2_proofs::dev::CircuitLayout::default()
            .render(5, &circuit, &root)
            .unwrap();
    }
}

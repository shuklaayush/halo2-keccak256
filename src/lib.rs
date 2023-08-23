mod columns;

use halo2_proofs::{arithmetic::Field, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

use columns::{reg_preimage, reg_step};
// use columns::{NUM_COLUMNS};

/// Number of rounds in a Keccak permutation.
pub(crate) const NUM_ROUNDS: usize = 24;

/// Number of 64-bit elements in the Keccak permutation input.
pub(crate) const NUM_INPUTS: usize = 25;

const NUM_COLUMNS: usize = 49;

#[derive(Debug, Clone)]
struct KeccakConfig {
    pub cols: [Column<Advice>; NUM_COLUMNS],
    pub selector: Selector,
    pub instance: Column<Instance>,
    pub constant: Column<Fixed>,
}

#[derive(Debug, Clone)]
struct KeccakChip<F: Field> {
    config: KeccakConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> KeccakChip<F> {
    pub fn construct(config: KeccakConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> KeccakConfig {
        let selector = meta.selector();
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        meta.enable_equality(instance);
        meta.enable_constant(constant);

        let cols: [Column<Advice>; NUM_COLUMNS] = (0..NUM_COLUMNS)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Round flags
        for i in 0..NUM_ROUNDS {
            meta.enable_equality(cols[reg_step(i)]);

            meta.create_gate("round_flags", |meta| {
                let s = meta.query_selector(selector);
                let current_round_flag = meta.query_advice(cols[reg_step(i)], Rotation::cur());
                let next_round_flag =
                    meta.query_advice(cols[reg_step((i + 1) % NUM_ROUNDS)], Rotation::next());
                vec![s * (next_round_flag - current_round_flag)]
            });
        }

        // Preimages
        for x in 0..5 {
            for y in 0..5 {
                meta.enable_equality(cols[reg_preimage(x, y)]);

                meta.create_gate("preimage", |meta| {
                    let s = meta.query_selector(selector);
                    let preimage = reg_preimage(x, y);
                    let diff = meta.query_advice(cols[preimage], Rotation::cur())
                        - meta.query_advice(cols[preimage], Rotation::next());
                    vec![s * diff]
                });
            }
        }

        KeccakConfig {
            cols,
            selector,
            instance,
            constant,
        }
    }

    pub fn assign(&self, mut layouter: impl Layouter<F>) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "keccak table",
            |mut region| {
                let mut preimage_cells = Vec::with_capacity(5 * 5);
                // Populate the preimage for first row.
                for x in 0..5 {
                    for y in 0..5 {
                        let preimage = reg_preimage(x, y);
                        preimage_cells.push(region.assign_advice_from_instance(
                            || "preimage",
                            self.config.instance,
                            y * 5 + x,
                            self.config.cols[preimage],
                            0,
                        )?);
                    }
                }

                // Assign first row
                let mut cells = Vec::with_capacity(NUM_ROUNDS);

                cells.push(region.assign_advice_from_constant(
                    || "1",
                    self.config.cols[reg_step(0)],
                    0,
                    F::ONE,
                )?);

                for col in 1..NUM_ROUNDS {
                    cells.push(region.assign_advice_from_constant(
                        || "0",
                        self.config.cols[reg_step(col)],
                        0,
                        F::ZERO,
                    )?);
                }

                // Assign remaining rows
                for round in 0..NUM_ROUNDS - 1 {
                    self.config.selector.enable(&mut region, round)?;

                    let mut new_cells = Vec::with_capacity(NUM_ROUNDS);
                    for col in 0..NUM_ROUNDS {
                        new_cells.push(region.assign_advice(
                            || "advice",
                            self.config.cols[reg_step(col)],
                            round + 1,
                            || cells[(col + NUM_ROUNDS - 1) % NUM_ROUNDS].value().copied(),
                        )?);
                    }
                    cells = new_cells;

                    for x in 0..5 {
                        for y in 0..5 {
                            let preimage = reg_preimage(x, y);
                            region.assign_advice(
                                || "preimage",
                                self.config.cols[preimage],
                                round + 1,
                                || preimage_cells[x * 5 + y].value().copied(),
                            )?;
                        }
                    }
                }

                Ok(cells[NUM_ROUNDS - 1].clone())
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

impl<F: Field> Circuit<F> for KeccakCircuit<F> {
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

use ff::PrimeField;
use halo2_proofs::plonk::Expression;

pub(crate) fn xor<F: PrimeField>(xs: &[F]) -> F {
    xs.into_iter().fold(F::ZERO, |acc, &x| {
        debug_assert!(x == F::ZERO || x == F::ONE);
        x + acc - x * acc * F::from(2)
    })
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor_gen<F: PrimeField>(x: Expression<F>, y: Expression<F>) -> Expression<F> {
    x.clone() + y.clone() - x * y * Expression::Constant(F::from(2))
}

/// Computes the arithmetic generalization of `xor3(x, y, z)`.
pub(crate) fn xor3_gen<F: PrimeField>(
    x: Expression<F>,
    y: Expression<F>,
    z: Expression<F>,
) -> Expression<F> {
    xor_gen(x, xor_gen(y, z))
}

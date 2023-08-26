use crate::halo2_proofs::{circuit::*, plonk::*};
use ff::Field;

/// Assign advice to physical region.
#[inline(always)]
pub fn assign_advice<F: Field>(
    region: &mut Region<F>,
    _annotation: &str,
    column: Column<Advice>,
    offset: usize,
    value: Value<F>,
) {
    #[cfg(feature = "halo2-axiom")]
    {
        region.assign_advice(column, offset, value);
    }
    #[cfg(not(feature = "halo2-axiom"))]
    {
        region
            .assign_advice(|| _annotation, column, offset, || value)
            .unwrap();
    }
}

use crate::halo2_proofs_shim::{circuit::*, plonk::*};
use ff::Field;

/// Assign advice to physical region.
#[inline(always)]
pub fn assign_advice<F: Field>(
    region: &mut Region<F>,
    _annotation: impl Into<String>,
    column: Column<Advice>,
    offset: usize,
    value: Value<impl Into<Assigned<F>>>,
) {
    #[cfg(feature = "axiom-backend")]
    {
        region.assign_advice(column, offset, value);
    }
    #[cfg(not(feature = "axiom-backend"))]
    {
        region.assign_advice(|| _annotation, column, offset, || value);
    }
}

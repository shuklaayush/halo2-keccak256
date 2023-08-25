#[cfg(all(feature = "pse-backend", feature = "zcash-backend"))]
compile_error!(
    "feature \"pse-backend\" and feature \"zcash-backend\" cannot be enabled at the same time"
);

#[cfg(feature = "pse-backend")]
pub use halo2_proofs_pse::*;

#[cfg(feature = "zcash-backend")]
pub use halo2_proofs_zcash::*;

#[cfg(all(
    not(feature = "axiom-backend"),
    not(feature = "pse-backend"),
    not(feature = "zcash-backend")
))]
compile_error!("no backend enabled");

#[cfg(any(
    all(feature = "axiom-backend", feature = "pse-backend",),
    all(feature = "axiom-backend", feature = "zcash-backend"),
    all(feature = "pse-backend", feature = "zcash-backend"),
))]
compile_error!("only one backend can be enabled at a time");

#[cfg(feature = "axiom-backend")]
pub use halo2_proofs_axiom::*;

#[cfg(feature = "pse-backend")]
pub use halo2_proofs_pse::*;

#[cfg(feature = "zcash-backend")]
pub use halo2_proofs_zcash::*;

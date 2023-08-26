#[cfg(all(
    not(feature = "halo2-axiom"),
    not(feature = "halo2-pse"),
    not(feature = "halo2-zcash")
))]
compile_error!("no backend enabled");

#[cfg(any(
    all(feature = "halo2-axiom", feature = "halo2-pse",),
    all(feature = "halo2-axiom", feature = "halo2-zcash"),
    all(feature = "halo2-pse", feature = "halo2-zcash"),
))]
compile_error!("only one backend can be enabled at a time");

#[cfg(feature = "halo2-axiom")]
pub use halo2_proofs_axiom::*;

#[cfg(feature = "halo2-pse")]
pub use halo2_proofs_pse::*;

#[cfg(feature = "halo2-zcash")]
pub use halo2_proofs_zcash::*;

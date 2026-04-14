//! Privacy subsystems (Dandelion++, Tor, future PeerId rotation).
//!
//! **Requirements:** STR-004 / SPEC Section 10.3 — submodules are individually feature-gated.
//! **Domain docs:** [`docs/requirements/domains/privacy/`](../../../docs/requirements/domains/privacy/).
//!
//! ## Rationale
//!
//! The `privacy` directory exists whenever **any** privacy feature is on, but each file only
//! compiles under its own flag. That matches the STR-004 examples (`#[cfg(feature = "dandelion")] pub mod dandelion`)
//! while allowing `tor` without `dandelion`.

#[cfg(feature = "dandelion")]
pub mod dandelion;

#[cfg(feature = "tor")]
pub mod tor;

//! Privacy subsystems (Dandelion++, PeerId rotation, Tor).
//!
//! **Module tree:** SPEC Section 10.1 (`privacy/`). STR-002 omitted this directory;
//! STR-003 pulls in `dandelion` for the [`StemTransaction`] re-export behind feature `dandelion`.
//!
//! **Requirements:** `docs/requirements/domains/privacy/`.

pub mod dandelion;

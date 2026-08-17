//! `ahl-mirror` — an independent AHL log mirror for the `ahl-adaptor-atl-v1` profile.
//!
//! # What this crate is
//!
//! The AHL core specification's log-binding contract (core spec §3) requires two interfaces
//! that a stock ATL deployment does not serve: retrieval of an entry's bytes by AHL entry id
//! (contract item 4, adaptor profile §10.1.1) and authenticated range enumeration with proof
//! of completeness and order (contract item 5, adaptor profile §10.2-§10.5). At conformance
//! level L3, both MUST be available from a party outside the producer's control (core spec
//! §3.5). `ahl-mirror` is that party: it stores entry bytes as they are anchored and serves
//! them back, content-addressed and self-checking, together with the canonical checkpoint
//! series adaptor profile §5.2.2 requires and the consistency proofs between series members
//! that its stored material can support.
//!
//! An entry becomes retrievable/enumerable only once it carries cryptographic evidence of
//! anchoring — a Merkle inclusion proof against a checkpoint this mirror has itself
//! authenticated — never on the strength of a submitted claim alone (see [`ingest`],
//! [`store`]). Checkpoint-signing keys are resolved the way the profile resolves them: from
//! the `manifest` entries this mirror already holds canonically, bootstrapped from a
//! configured genesis anchor (see [`manifest`]), honouring per-key activation bounds. The
//! checkpoint series tracks whether it is provably gap-free at a declared cadence, and
//! `ITUB` reports unavailable rather than a guess wherever it is not (see [`checkpoint`]).
//!
//! # What this crate is not
//!
//! It does not walk the statement graph (inputs, outputs, triggers, closure), does not
//! verify producer signatures, and does not validate manifest-chain linkage
//! (`predecessor` pointers, signature-based chain-of-trust) — those are a verifier's job
//! (core spec §6). The one narrow exception is [`manifest`]: it reads the `type` and `log`
//! fields of `manifest`-typed *canonical* entries, for the sole purpose of resolving
//! checkpoint-signing keys and cadence the way adaptor profile §7.3 requires, trusting a
//! manifest entry's content purely because of *where* it sits (core spec §2.3.5), not
//! because its own signature or lineage was checked. See the crate's `README.md` ("Scope and
//! honest gaps") for the specific places the profile assumes more context than a standalone
//! mirror has, and how this crate resolves that.
//!
//! # Reuse, not reimplementation
//!
//! Canonicalization, family-string parsing, envelope/checkpoint identifiers, and range-proof
//! generation/verification are reused from [`ahl_core`] rather than reimplemented — the same
//! anti-drift discipline `ahl-core` itself follows against `atl-core`. This crate calls
//! `atl-core`'s Merkle primitives directly only where `ahl-core` does not expose them
//! (consistency proofs, and the ATL-specific log-leaf construction of adaptor profile §4.2,
//! which is deliberately different from the plain AHL tree leaf hashing `ahl-core` uses for
//! batch/input-set/disposition trees).
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(missing_docs, rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
// `ahl-core`'s pinned `atl-core` revision brings `thiserror` 1.x (and the `syn` 2.x it needs)
// while this crate's own `thiserror` is 2.x (needing `syn` 3.x): see ahl-core's Cargo.toml
// for the fuller rationale. Not actionable from library code.
#![allow(clippy::multiple_crate_versions)]
// Test code favours `.expect()` messages that document the fixture and, occasionally,
// `panic!` inside a match arm the test proves unreachable. Production code paths are held to
// the deny above without exception.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)
)]

pub mod checkpoint;
pub mod config;
pub mod error;
pub mod http;
pub mod ingest;
pub mod manifest;
pub mod metadata;
pub mod range;
pub mod retrieval;
pub mod store;

pub use config::{Config, ConfigSpec, TrustedLogKey, TrustedLogKeySpec};
pub use error::{MirrorError, MirrorResult};
pub use store::Store;

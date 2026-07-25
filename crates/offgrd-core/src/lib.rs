#![forbid(unsafe_code)]
//! offgrd-core: the in-process event pipeline.
//!
//! This crate turns "one-off CLI commands that print stuff" into
//! "collectors that push normalized Events onto a shared bus, which
//! anything (storage, correlation engine, UI, CLI) can subscribe to."
//! It deliberately does *not* know about Windows APIs, ETW, or any
//! specific data source — that's the job of collector implementations
//! that live elsewhere (starting with offgrd-cli's `platform` module,
//! which will move behind this trait in a later milestone) and depend
//! on this crate, not the other way around.

pub mod bus;
pub mod collector;
pub mod storage;

pub use bus::EventBus;
pub use collector::Collector;
pub use storage::EventStore;

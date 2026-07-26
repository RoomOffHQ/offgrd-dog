#![forbid(unsafe_code)]
//! offgrd-common
//!
//! Shared, dependency-light types used across every OffGrd Dog crate:
//! the normalized `Event` envelope, process references, and the
//! category/severity enums. Collectors (ETW, registry, network, etc.)
//! all convert their raw, source-specific data into these types so the
//! rest of the pipeline (storage, correlation, UI, CLI) never needs to
//! know where an event came from.
//!
//! This crate intentionally has almost no dependencies and no logic
//! beyond simple constructors, so it compiles fast and can be shared
//! by the (eventual) kernel-mode FFI boundary without pulling in a
//! heavy dependency tree.

pub mod alert;
pub mod event;
pub mod process;

pub use alert::Alert;
pub use event::{Event, EventCategory, EventPayload, EventSource, Severity};
pub use process::ProcessRef;

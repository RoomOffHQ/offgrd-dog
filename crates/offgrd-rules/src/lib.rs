#![forbid(unsafe_code)]
//! offgrd-rules: a deliberately small, stateless rule-matching engine.
//!
//! Scope on purpose: a rule matches against **one event at a time** —
//! no cross-event correlation, no sliding windows, no process-graph
//! walking yet. That's real complexity (the "Word → PowerShell →
//! network → injection" chain from the architecture doc) that
//! deserves its own design once we have several real collectors
//! feeding real data to test it against. This crate is the honest
//! first step: field-level pattern matching, Sigma-flavored YAML,
//! nothing more.

pub mod alert;
pub mod rule;
pub mod ruleset;

pub use alert::Alert;
pub use rule::{Condition, Rule};
pub use ruleset::RuleSet;

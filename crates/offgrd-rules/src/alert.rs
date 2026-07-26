//! The `Alert` type itself now lives in `offgrd-common` (see that
//! crate's `alert` module for the full rationale: it lets
//! `offgrd-core`'s `EventStore` persist alerts without depending on
//! this crate). This module just re-exports it for convenience so
//! existing `use offgrd_rules::Alert` imports keep working, plus the
//! one bit of construction logic that *does* belong here: building an
//! `Alert` from a matched `Rule`.

pub use offgrd_common::Alert;

use crate::Rule;
use offgrd_common::Event;

/// Builds an `Alert` from a rule that matched `event`. Free function
/// rather than an inherent method on `Alert` (which lives in a
/// different crate now) or a method on `Rule` (kept here instead,
/// next to where `Alert` construction conceptually belongs).
pub fn alert_from_rule_match(rule: &Rule, event: &Event) -> Alert {
    Alert::new(&rule.id, &rule.title, rule.severity, event.id)
}

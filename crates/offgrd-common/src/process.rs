use serde::{Deserialize, Serialize};

/// A lightweight, serializable reference to a Windows process.
///
/// This is deliberately a snapshot, not a live handle: events are
/// normalized data, not live OS resources, so they can be stored,
/// exported, and replayed without holding onto any process handle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessRef {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    /// True if `parent_pid` does not match the process that actually
    /// created this one (per OS bookkeeping vs. actual creator handle).
    /// Populated later by the correlation engine, not by collectors.
    pub parent_pid_spoofed: Option<bool>,
}

impl ProcessRef {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            parent_pid: None,
            image_path: None,
            command_line: None,
            parent_pid_spoofed: None,
        }
    }

    pub fn with_parent(mut self, parent_pid: u32) -> Self {
        self.parent_pid = Some(parent_pid);
        self
    }

    pub fn with_image_path(mut self, path: impl Into<String>) -> Self {
        self.image_path = Some(path.into());
        self
    }

    pub fn with_command_line(mut self, cmd: impl Into<String>) -> Self {
        self.command_line = Some(cmd.into());
        self
    }
}

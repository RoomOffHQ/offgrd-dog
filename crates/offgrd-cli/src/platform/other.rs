//! Non-Windows stand-in. OffGrd Dog's real target is Windows 10/11;
//! this module exists solely so `cargo build`/`cargo test` work on a
//! contributor's Linux/macOS machine for the OS-agnostic crates
//! (offgrd-common, rule parsing, etc.) without requiring a Windows box
//! just to run `cargo check` on the whole workspace. It returns an
//! explicit error rather than silently faking data.

use anyhow::{bail, Result};
use offgrd_common::ProcessRef;

pub fn list_processes() -> Result<Vec<ProcessRef>> {
    bail!(
        "offgrd-cli 'ps' is only implemented on Windows (uses Win32 Toolhelp32 APIs). \
         Build and run this on Windows 10/11."
    )
}

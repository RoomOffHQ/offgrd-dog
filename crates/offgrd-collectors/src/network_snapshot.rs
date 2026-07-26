//! Network Monitor — active TCP connection snapshot, via Win32's
//! `GetExtendedTcpTable` (IP Helper API). No admin rights required:
//! this is the same data `netstat -ano` shows any user.
//!
//! Scope on purpose, matching the project's "ship the honest MVP"
//! pattern: IPv4 TCP only for this first pass. IPv6 and UDP
//! (`GetExtendedTcpTable` has an `AF_INET6` variant;
//! `GetExtendedUdpTable` is the connectionless equivalent) are
//! natural, mechanical follow-ups once this is verified working —
//! not attempted together in one unverified pass.

use anyhow::{Context, Result};
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::mem::size_of;
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    /// Returns every active IPv4 TCP connection visible to the
    /// current user, as normalized `Event`s.
    pub fn list_tcp_connections() -> Result<Vec<Event>> {
        // `GetExtendedTcpTable` is a two-call API: first call with a
        // too-small (or zero) buffer to learn the required size, then
        // a real call with a correctly-sized buffer. This is the
        // documented, standard pattern for this API, not a guess.
        let mut size: u32 = 0;

        // SAFETY: passing a null buffer pointer with `size` reporting
        // the buffer as 0 bytes is the documented way to query the
        // required buffer size; the API does not write through the
        // pointer in this mode, only writes the required size into
        // `size`. `bOrder=true` (sorted), `ulAf=AF_INET` (IPv4),
        // `TableClass=TCP_TABLE_OWNER_PID_ALL` (include owning pid).
        let query_result = unsafe {
            GetExtendedTcpTable(
                None,
                &mut size,
                true,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if query_result != ERROR_INSUFFICIENT_BUFFER.0 && query_result != NO_ERROR.0 {
            anyhow::bail!("GetExtendedTcpTable size query failed with code {query_result}");
        }
        if size == 0 {
            return Ok(Vec::new()); // No connections at all — valid, not an error.
        }

        let mut buffer = vec![0u8; size as usize];

        // SAFETY: `buffer` is sized exactly to what the previous call
        // reported as required via `size`, and remains valid/mutably
        // borrowed for the duration of this call; the API writes at
        // most `size` bytes into it, matching the buffer's actual
        // length.
        let result = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                true,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if result != NO_ERROR.0 {
            anyhow::bail!("GetExtendedTcpTable failed with code {result}");
        }

        // SAFETY: `buffer` was populated by the successful call above
        // and is large enough (per the size query) to hold a
        // `MIB_TCPTABLE_OWNER_PID` header followed by `dwNumEntries`
        // `MIB_TCPROW_OWNER_PID` rows — the documented layout of this
        // structure, which is why the two-call size-query dance above
        // is required before this cast is valid.
        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let num_entries = table.dwNumEntries as usize;

        // SAFETY: `table.table` is declared as a 1-element array in
        // the Windows metadata (the classic C "flexible array member"
        // idiom); the real row count is `num_entries`, and the buffer
        // was sized to fit exactly that many rows after the header —
        // reading `num_entries` rows from this pointer stays within
        // `buffer`'s allocation.
        let rows: &[MIB_TCPROW_OWNER_PID] = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), num_entries)
        };

        Ok(rows.iter().map(row_to_event).collect())
    }

    fn row_to_event(row: &MIB_TCPROW_OWNER_PID) -> Event {
        Event::new(
            EventSource::Snapshot,
            EventCategory::Network,
            EventPayload::NetworkConnectionObserved {
                pid: Some(row.dwOwningPid),
                local_addr: ipv4_to_string(row.dwLocalAddr),
                local_port: port_from_network_order(row.dwLocalPort),
                remote_addr: ipv4_to_string(row.dwRemoteAddr),
                remote_port: port_from_network_order(row.dwRemotePort),
                state: tcp_state_label(row.dwState),
            },
        )
    }

    /// `dwLocalAddr`/`dwRemoteAddr` are IPv4 addresses in network byte
    /// order (big-endian), same as a `struct in_addr` — standard
    /// dotted-quad decoding.
    fn ipv4_to_string(addr: u32) -> String {
        let bytes = addr.to_le_bytes(); // to_le_bytes because the u32 already holds network-order octets in memory order.
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }

    /// Ports in this structure are stored in the low 16 bits, in
    /// network byte order — `GetExtendedTcpTable`'s well-documented
    /// quirk (unlike the rest of the struct, ports need an explicit
    /// byte-swap from network to host order).
    fn port_from_network_order(port_field: u32) -> u16 {
        u16::from_be(port_field as u16)
    }

    fn tcp_state_label(state: u32) -> String {
        // MIB_TCP_STATE_* constants, per the documented IP Helper API.
        match state {
            1 => "CLOSED",
            2 => "LISTENING",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            other => return format!("UNKNOWN({other})"),
        }
        .to_string()
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_tcp_connections() -> Result<Vec<Event>> {
        anyhow::bail!(
            "Network Monitor uses Win32's IP Helper API and is only implemented on Windows."
        )
    }
}

#[cfg(windows)]
pub use windows_impl::list_tcp_connections;
#[cfg(not(windows))]
pub use other_impl::list_tcp_connections;

/// The `offgrd_core::Collector` wrapper — same shape as
/// `ProcessSnapshotCollector`, one-shot per `run()` call.
pub struct NetworkSnapshotCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for NetworkSnapshotCollector {
    fn name(&self) -> &'static str {
        "network-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_tcp_connections().context("failed to enumerate TCP connections")?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}

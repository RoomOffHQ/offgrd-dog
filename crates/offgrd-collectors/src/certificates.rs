//! Certificate Inspector (installed-certificate variant) — enumerates
//! certificates in the local machine's system certificate stores via
//! `CertOpenSystemStoreW`/`CertEnumCertificatesInStore`.
//!
//! Scope on purpose: this is "what's in the trust store," not "TLS
//! chain of a live connection" — the latter needs hooking into
//! Schannel/ETW and is a separate, harder capability (see the
//! architecture doc's TLS Certificate Inspector module). Checking
//! installed roots/intermediates is still genuinely useful on its
//! own: a rogue CA certificate silently added to the ROOT store is a
//! real, well-known persistence/MITM technique.

use anyhow::Result;
use chrono::{DateTime, Utc};
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

/// Stores checked. "ROOT" (trusted root CAs) and "CA" (intermediate
/// CAs) are the two most security-relevant for spotting an
/// unexpectedly-added trust anchor; "MY" (personal/client certs) is
/// included since unexpected client certs can indicate credential
/// misuse. Not exhaustive — "TrustedPublisher", "Disallowed", etc.
/// are real stores too, left for a follow-up.
const STORE_NAMES: &[&str] = &["ROOT", "CA", "MY"];

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertGetNameStringW, CertOpenSystemStoreW,
        CERT_CONTEXT, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_STORE_PROV_SYSTEM_W,
    };
    use windows::Win32::Foundation::FILETIME;

    pub fn list_certificates() -> Result<Vec<Event>> {
        let mut events = Vec::new();

        for store_name in STORE_NAMES {
            match list_store(store_name) {
                Ok(mut certs) => events.append(&mut certs),
                Err(err) => {
                    eprintln!("offgrd: could not read certificate store '{store_name}': {err:#} (skipping)");
                }
            }
        }

        Ok(events)
    }

    fn list_store(store_name: &str) -> Result<Vec<Event>> {
        let store_name_wide = to_wide(store_name);

        // SAFETY: `CertOpenSystemStoreW` with a null HCRYPTPROV_LEGACY
        // (unused for CERT_STORE_PROV_SYSTEM_W) and a valid,
        // NUL-terminated store-name string is the documented way to
        // open a named system store for the current user context.
        let store = unsafe {
            CertOpenSystemStoreW(None, PCWSTR(store_name_wide.as_ptr()))
        }?;

        struct StoreGuard(windows::Win32::Security::Cryptography::HCERTSTORE);
        impl Drop for StoreGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` is the valid store handle opened
                // above; `CertCloseStore` with flags=0 is safe to call
                // once on any valid, still-open store handle.
                unsafe {
                    let _ = CertCloseStore(self.0, 0);
                }
            }
        }
        let _guard = StoreGuard(store);

        let mut events = Vec::new();
        let mut cert_ptr: *const CERT_CONTEXT = std::ptr::null();

        loop {
            // SAFETY: `store` is a valid, open store handle;
            // `cert_ptr` starts null (meaning "give me the first
            // certificate") and on each subsequent call is the
            // previous call's return value, per this API's documented
            // enumeration contract (it also frees the previous
            // context internally when advancing, so we must NOT
            // separately free `cert_ptr` ourselves between calls).
            cert_ptr = unsafe { CertEnumCertificatesInStore(store, cert_ptr) };
            if cert_ptr.is_null() {
                break; // No more certificates in this store.
            }

            // SAFETY: `cert_ptr` was just returned non-null by the
            // call above, meaning it points at a valid `CERT_CONTEXT`
            // owned by the store for at least as long as the store
            // remains open and until the next enumeration call.
            let cert = unsafe { &*cert_ptr };

            match cert_context_to_event(store_name, cert) {
                Ok(event) => events.push(event),
                Err(err) => {
                    eprintln!("offgrd: skipping unreadable certificate in '{store_name}': {err:#}");
                }
            }
        }

        Ok(events)
    }

    fn cert_context_to_event(store_name: &str, cert: &CERT_CONTEXT) -> Result<Event> {
        let subject = get_name_string(cert, false)?;
        let issuer = get_name_string(cert, true)?;
        let thumbprint = compute_thumbprint(cert)?;

        // SAFETY: `cert.pCertInfo` is guaranteed non-null and valid
        // for a valid `CERT_CONTEXT` per the API's documented
        // invariants; `NotBefore`/`NotAfter` are plain `FILETIME`
        // value fields (not pointers) within the pointed-to struct.
        let cert_info = unsafe { &*cert.pCertInfo };
        let not_before = filetime_to_datetime(cert_info.NotBefore);
        let not_after = filetime_to_datetime(cert_info.NotAfter);

        Ok(Event::new(
            EventSource::Snapshot,
            EventCategory::Certificates,
            EventPayload::CertificateObserved {
                store_name: store_name.to_string(),
                subject,
                issuer,
                thumbprint,
                not_before,
                not_after,
            },
        ))
    }

    fn get_name_string(cert: &CERT_CONTEXT, issuer: bool) -> Result<String> {
        let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };

        // SAFETY: first call with a null buffer/0 size is the
        // documented way to query the required buffer length
        // (returned as a character count, including the NUL
        // terminator) for `CertGetNameStringW`.
        let len = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                None,
                None,
            )
        };
        if len <= 1 {
            return Ok(String::new()); // No name available — valid, not an error.
        }

        let mut buffer = vec![0u16; len as usize];
        // SAFETY: `buffer` is sized exactly to `len` (the value the
        // same API just reported as required), and remains valid for
        // the duration of this call.
        let written = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                None,
                Some(&mut buffer),
            )
        };
        let effective_len = written.min(buffer.len() as u32) as usize;
        let end = buffer[..effective_len]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(effective_len);
        Ok(String::from_utf16_lossy(&buffer[..end]))
    }

    fn compute_thumbprint(cert: &CERT_CONTEXT) -> Result<String> {
        // SAFETY: `cert.pbCertEncoded`/`cert.cbCertEncoded` describe
        // the DER-encoded certificate bytes owned by this valid
        // `CERT_CONTEXT`, guaranteed valid for at least the lifetime
        // of the context itself.
        let der = unsafe {
            std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize)
        };

        // The conventional certificate "thumbprint" is a SHA-1 digest
        // of the DER encoding. Computed here with a minimal, dependency-free
        // SHA-1 rather than pulling in a crypto crate for one hash —
        // acceptable since this is a non-security-critical identifier
        // (display/lookup only), not used for any trust decision.
        Ok(hex_encode(&sha1(der)))
    }

    fn filetime_to_datetime(ft: FILETIME) -> DateTime<Utc> {
        // FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
        let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
        const EPOCH_DIFFERENCE_100NS: u64 = 116_444_736_000_000_000; // 1601 -> 1970
        let unix_100ns = ticks.saturating_sub(EPOCH_DIFFERENCE_100NS);
        let unix_seconds = (unix_100ns / 10_000_000) as i64;
        DateTime::from_timestamp(unix_seconds, 0).unwrap_or_else(Utc::now)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Minimal, self-contained SHA-1 (not used for any security
    /// decision — see `compute_thumbprint`'s doc comment — so a
    /// hand-rolled implementation avoiding an extra dependency is an
    /// acceptable tradeoff here specifically).
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for (i, &wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }

        let mut out = [0u8; 20];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[cfg(test)]
    mod sha1_tests {
        use super::*;

        #[test]
        fn sha1_matches_known_vector_for_empty_input() {
            // echo -n "" | sha1sum
            let digest = sha1(b"");
            assert_eq!(hex_encode(&digest), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        }

        #[test]
        fn sha1_matches_known_vector_for_abc() {
            // echo -n "abc" | sha1sum
            let digest = sha1(b"abc");
            assert_eq!(hex_encode(&digest), "a9993e364706816aba3e25717850c26c9cd0d89d");
        }
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_certificates() -> Result<Vec<Event>> {
        anyhow::bail!(
            "Certificate Inspector uses the Windows Crypto API and is only implemented on Windows."
        )
    }
}

#[cfg(windows)]
pub use windows_impl::list_certificates;
#[cfg(not(windows))]
pub use other_impl::list_certificates;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call,
/// same shape as the other snapshot collectors.
pub struct CertificatesCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for CertificatesCollector {
    fn name(&self) -> &'static str {
        "certificates-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_certificates()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}

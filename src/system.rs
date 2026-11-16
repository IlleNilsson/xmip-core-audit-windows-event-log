//! The Event Log's and the registry's C interfaces: whether a source is
//! registered under the Application log, and one entry reported under it.
//!
//! The one file of this crate that may hold unsafe code (ADR-0050,
//! amendment 2026-09-25): the Event Log and the registry are C interfaces
//! and are reached no other way. Every block says where its pointers come
//! from, how long they live and who frees what they hand back.
#![allow(unsafe_code)]

use std::ptr;

use audit::AuditError;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
};

/// Where the Application log's sources are registered.
const SOURCES: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application";

/// Every Xmip entry is event 1000: the id whose message is the text as given,
/// under the registered source and under the stand-in alike.
const EVENT: u32 = 1000;

/// Whether `source` is registered under the Application log.
pub(crate) fn registered(source: &str) -> bool {
    let Ok(path) = codec::wide::encode(&format!(r"{SOURCES}\{source}")) else {
        return false;
    };
    let mut key: HKEY = ptr::null_mut();

    // SAFETY: `path` is a NUL-terminated UTF-16 string owned by this frame
    // and outlives the call; `key` is a local the call writes the opened
    // key's handle into. HKEY_LOCAL_MACHINE is a predefined key, never freed.
    let opened =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &raw mut key) };

    if opened != ERROR_SUCCESS {
        return false;
    }

    // SAFETY: `key` is the handle RegOpenKeyExW opened above and nothing else
    // holds it; this closes it once, and it is not used again.
    unsafe { RegCloseKey(key) };
    true
}

/// One entry under `source`.
pub(crate) fn report(source: &str, kind: u16, text: &str) -> Result<(), AuditError> {
    let name = wide(source)?;
    let message = wide(text)?;

    // SAFETY: `name` is a NUL-terminated UTF-16 string owned by this frame and
    // outlives the call; a null server name is this machine. The handle
    // returned is this process's and is released below by
    // DeregisterEventSource, exactly once.
    let log = unsafe { RegisterEventSourceW(ptr::null(), name.as_ptr()) };

    if log.is_null() {
        return Err(AuditError::new(format!(
            "the Windows Event Log refused the source {source}: {}",
            std::io::Error::last_os_error()
        )));
    }

    let strings = [message.as_ptr()];

    // SAFETY: `log` is the live handle registered above. `strings` holds one
    // pointer to `message`, a NUL-terminated UTF-16 string owned by this
    // frame, and both outlive the call; the count passed is that one. No user
    // SID (null) and no raw data (null, size 0). The Event Log copies what it
    // keeps; nothing it is handed is freed by it.
    let reported = unsafe {
        ReportEventW(
            log,
            kind,
            0,
            EVENT,
            ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            ptr::null(),
        )
    };
    let failure = std::io::Error::last_os_error();

    // SAFETY: `log` is the handle RegisterEventSourceW returned above; it is
    // released here once and not used again.
    unsafe { DeregisterEventSource(log) };

    if reported == 0 {
        return Err(AuditError::new(format!(
            "the Windows Event Log refused the entry: {failure}"
        )));
    }

    Ok(())
}

/// `text` as a wide string, the only text the Windows API reads, refused
/// where it holds a NUL the Event Log would cut it short at.
fn wide(text: &str) -> Result<codec::wide::Wide, AuditError> {
    codec::wide::encode(text)
        .map_err(|why| AuditError::new(format!("the Windows Event Log takes no NUL: {why}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_crosses_as_nul_terminated_utf_16() {
        assert_eq!(wide("Xö").expect("wide").units(), [0x58, 0xf6, 0]);
        assert!(wide("X\0ö").is_err(), "a NUL inside is refused");
    }
}

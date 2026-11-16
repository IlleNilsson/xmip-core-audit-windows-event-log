//! The Windows Event Log, ADR-0062's operating system's log on Windows: an
//! entry in the Application log, event 1000, under the event source
//! `XMIP_EVENT_SOURCE` (`xmip_operate.h` section 9, ADR-0062 clause 3),
//! written through the Event Log's own C interface.
//!
//! Registering the source needs elevation once; the prerequisite installer
//! does it. Until it has, an entry is written under the Application log's
//! existing `.NET Runtime` source, whose event 1000 shows the text as given,
//! and its first sentence says why. The `windows-event-log` technology of
//! `xmip-core-audit` in `architecture.toml`: [`WindowsEventLog`] is an
//! `audit::operating_system_log::OperatingSystemLog`, which the program that
//! runs hands its audit as it starts. Windows only: on any other platform
//! this crate is empty, and the `syslog` technology is the log there.
//!
//! The Event Log and the registry are reached in `src/system.rs`, the one
//! file of this crate that may hold unsafe code (ADR-0050, amendment
//! 2026-09-25).
#![cfg(windows)]

mod system;

use abi::operate::audit::{EVENT_SOURCE, EVENT_SOURCE_UNREGISTERED};
use audit::AuditError;
use audit::operating_system_log::OperatingSystemLog;
use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
};
use xcore::Severity;

use system::{registered, report};

/// The source an entry goes under while `EVENT_SOURCE` is not registered.
const STAND_IN: &str = ".NET Runtime";

/// The Event Log's limit on one entry's text is 31 839 characters.
const MOST: usize = 31_000;

/// The Windows Event Log's Application log.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowsEventLog;

impl OperatingSystemLog for WindowsEventLog {
    /// Write `text` at `severity`. Answers the log and source that took it.
    fn write(&self, severity: Severity, text: &str) -> Result<String, AuditError> {
        let kind = match severity {
            Severity::Error => EVENTLOG_ERROR_TYPE,
            Severity::Warning => EVENTLOG_WARNING_TYPE,
            Severity::Information => EVENTLOG_INFORMATION_TYPE,
        };
        let (source, entry) = if registered(EVENT_SOURCE) {
            (EVENT_SOURCE, text.to_string())
        } else {
            (STAND_IN, format!("{EVENT_SOURCE_UNREGISTERED} {text}"))
        };
        let entry: String = entry.chars().take(MOST).collect();

        report(source, kind, &entry)?;
        Ok(format!(
            "the Windows Event Log, Application, source {source}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_that_is_not_there_is_not_registered_and_the_stand_in_is() {
        assert!(!registered(
            "Xmip audit test source that is never registered"
        ));
        assert!(registered(STAND_IN), "{STAND_IN} ships with Windows");
    }

    #[test]
    #[ignore = "writes to this machine's Windows Event Log; run with --ignored to prove it"]
    fn an_entry_reaches_the_event_log() {
        let said = WindowsEventLog
            .write(
                Severity::Information,
                "written by xmip-core-audit-windows-event-log's own test",
            )
            .expect("written");

        assert!(
            said.starts_with("the Windows Event Log, Application"),
            "{said}"
        );
    }

    #[test]
    #[ignore = "writes to this machine's Windows Event Log; run with --ignored to prove it"]
    fn an_entry_under_the_stand_in_says_why() {
        let text = format!(
            "{EVENT_SOURCE_UNREGISTERED} written by xmip-core-audit-windows-event-log's own test"
        );

        report(STAND_IN, EVENTLOG_WARNING_TYPE, &text).expect("written");
    }
}

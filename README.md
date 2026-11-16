# xmip-core-audit-windows-event-log

The `windows-event-log` technology of `xmip-core-audit`: the operating
system's log on Windows, where a record goes when audit cannot persist it
(ADR-0062 clause 3). `WindowsEventLog` is an
`audit::operating_system_log::OperatingSystemLog`; the program that runs
hands it to audit as it starts (`operating_system_log::hand`), and audit's
fallback rule writes through it. The rule — when, and the sentence that
says why — is audit's; this crate writes the entry.

An entry in the Application log, event 1000, under the source `Xmip`, the
ABI header's `XMIP_EVENT_SOURCE`. Registering the source needs elevation
once — `Install-XmipPrerequisite -Install`, elevated, does it; until then
an entry goes under `.NET Runtime`, whose event 1000 shows the text as
given, and its first sentence says so. An entry is cut at 31,000
characters, under the Event Log's limit of 31,839.

The Event Log and the registry are C interfaces, called through
`windows-sys` from `src/system.rs`, the one file of this crate that may
hold unsafe code (ADR-0050, amendment 2026-09-25; `test/Unsafe.Test.ps1`
holds the list). Windows only: on any other platform this crate is empty,
and `xmip-core-audit-syslog` is the log there.

No test writes to the machine's log by default: the two that do — one
entry under `Xmip`, one under `.NET Runtime` — are ignored, and
`cargo test -- --ignored` runs them to prove it.

`architecture.toml` carries the maturity.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

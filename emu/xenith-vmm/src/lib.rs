//! Windows Hypervisor Platform backend with deterministic interpreter fallback.

mod runner;
mod whp;

#[cfg(all(test, windows))]
pub(crate) static WHP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub use runner::{WhpRunReason, WhpRunSummary};
pub use whp::{WhpError, WhpExecutionProof, WhpPartition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Interpreter,
    WindowsHypervisorPlatform,
}

#[must_use]
pub fn preferred_backend() -> Backend {
    if WhpPartition::is_available() {
        Backend::WindowsHypervisorPlatform
    } else {
        Backend::Interpreter
    }
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use std::path::PathBuf;

    #[derive(Debug, Default, Clone)]
    pub struct TraceCollector;

    impl TraceCollector {
        pub fn new() -> Self {
            Self
        }

        pub fn with_root(self, _root: impl Into<PathBuf>) -> Self {
            self
        }

        pub fn run(&self, _cmd: &[String]) -> Result<TraceReport, TraceError> {
            Err(TraceError::Unsupported(
                "ptrace tracing is only available on Linux",
            ))
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct TraceReport;

    #[derive(thiserror::Error, Debug)]
    pub enum TraceError {
        #[error("{0}")]
        Unsupported(&'static str),
    }
}

#[cfg(not(target_os = "linux"))]
pub use unsupported::*;

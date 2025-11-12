use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Metadata extracted from an OCI/Container image config that may impact runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    pub workdir: Option<PathBuf>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
}

impl ImageConfig {
    pub fn is_empty(&self) -> bool {
        self.workdir.is_none() && self.entrypoint.is_empty() && self.cmd.is_empty() && self.env.is_empty()
    }
}

/// Handle representing a prepared image rootfs and associated metadata.
pub struct ImageRoot {
    reference: String,
    rootfs_path: PathBuf,
    config: ImageConfig,
    cleanup: Option<Box<dyn CleanupHook>>,
}

impl ImageRoot {
    pub fn new(reference: impl Into<String>, rootfs_path: impl Into<PathBuf>, config: ImageConfig) -> Self {
        Self {
            reference: reference.into(),
            rootfs_path: rootfs_path.into(),
            config,
            cleanup: None,
        }
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn rootfs(&self) -> &Path {
        &self.rootfs_path
    }

    pub fn config(&self) -> &ImageConfig {
        &self.config
    }

    pub fn with_cleanup<F>(mut self, cleanup: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        self.cleanup = Some(Box::new(cleanup));
        self
    }

    pub fn detach_cleanup(mut self) -> Self {
        self.cleanup = None;
        self
    }

    pub fn into_parts(mut self) -> (String, PathBuf, ImageConfig) {
        self.cleanup = None;
        let reference = std::mem::take(&mut self.reference);
        let rootfs = std::mem::take(&mut self.rootfs_path);
        let config = std::mem::take(&mut self.config);
        (reference, rootfs, config)
    }
}

impl Drop for ImageRoot {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup.call();
        }
    }
}

trait CleanupHook: Send {
    fn call(self: Box<Self>);
}

impl<F> CleanupHook for F
where
    F: FnOnce(),
    F: Send + 'static,
{
    fn call(self: Box<Self>) {
        (*self)();
    }
}

/// Interface for backends that can materialize an image's root filesystem locally.
pub trait ImageRootProvider: Send + Sync {
    fn backend(&self) -> &'static str;

    fn prepare_root(&self, reference: &str) -> Result<ImageRoot, ImageProviderError>;
}

#[derive(Debug, Error)]
pub enum ImageProviderError {
    #[error("provider `{backend}` unavailable: {reason}")]
    Unavailable { backend: &'static str, reason: String },
    #[error("image reference is empty")]
    EmptyReference,
    #[error("image `{reference}` not found: {message}")]
    NotFound { reference: String, message: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl ImageProviderError {
    pub fn unavailable(backend: &'static str, reason: impl Into<String>) -> Self {
        Self::Unavailable {
            backend,
            reason: reason.into(),
        }
    }

    pub fn not_found(reference: impl Into<String>, message: impl Into<String>) -> Self {
        Self::NotFound {
            reference: reference.into(),
            message: message.into(),
        }
    }
}

impl fmt::Debug for ImageRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageRoot")
            .field("reference", &self.reference)
            .field("rootfs_path", &self.rootfs_path)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn config_default_is_empty() {
        let cfg = ImageConfig::default();
        assert!(cfg.is_empty());
    }

    #[test]
    fn cleanup_runs_on_drop() {
        let triggered = Arc::new(AtomicBool::new(false));
        {
            let flag = triggered.clone();
            let config = ImageConfig::default();
            let _root = ImageRoot::new("demo", "/tmp/root", config).with_cleanup(move || {
                flag.store(true, Ordering::SeqCst);
            });
        }
        assert!(triggered.load(Ordering::SeqCst));
    }

    #[test]
    fn into_parts_detaches_cleanup() {
        let triggered = Arc::new(AtomicBool::new(false));
        let flag = triggered.clone();
        let config = ImageConfig::default();
        let root = ImageRoot::new("demo", "/tmp/root", config).with_cleanup(move || {
            flag.store(true, Ordering::SeqCst);
        });
        let (_reference, _path, _config) = root.into_parts();
        assert!(!triggered.load(Ordering::SeqCst));
    }
}

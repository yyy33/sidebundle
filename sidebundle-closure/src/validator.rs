use std::path::{Path, PathBuf};

use log::{debug, info};

use crate::linker::{LinkerError, LinkerRunner};
use sidebundle_core::EntryBundlePlan;
use thiserror::Error;

/// Revalidates bundle contents by re-running the linker against packaged entries.
#[derive(Debug, Clone)]
pub struct BundleValidator {
    runner: LinkerRunner,
}

impl BundleValidator {
    pub fn new() -> Self {
        Self {
            runner: LinkerRunner::new(),
        }
    }

    pub fn with_runner(mut self, runner: LinkerRunner) -> Self {
        self.runner = runner;
        self
    }

    /// Validate every entry plan against the files located under `bundle_root`.
    pub fn validate(
        &self,
        bundle_root: &Path,
        plans: &[EntryBundlePlan],
    ) -> Result<(), ValidationError> {
        info!(
            "validating {} bundle entr{}",
            plans.len(),
            if plans.len() == 1 { "y" } else { "ies" }
        );
        for plan in plans {
            self.validate_entry(bundle_root, plan)?;
        }
        Ok(())
    }

    fn validate_entry(
        &self,
        bundle_root: &Path,
        plan: &EntryBundlePlan,
    ) -> Result<(), ValidationError> {
        let binary_path = bundle_root.join(&plan.binary_destination);
        if !binary_path.exists() {
            return Err(ValidationError::MissingBinary(binary_path));
        }
        if !plan.requires_linker {
            debug!(
                "entry `{}` is static, skipping linker validation",
                plan.display_name
            );
            return Ok(());
        }

        let linker_path = bundle_root.join(&plan.linker_destination);
        if !linker_path.exists() {
            return Err(ValidationError::MissingLinker(linker_path));
        }

        let search_paths: Vec<PathBuf> = plan
            .library_dirs
            .iter()
            .map(|dir| bundle_root.join(dir))
            .collect();

        self.runner
            .trace_dependencies(&linker_path, &binary_path, &search_paths)
            .map_err(|source| ValidationError::Linker {
                binary: binary_path,
                source,
            })?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("binary missing at {0}")]
    MissingBinary(PathBuf),
    #[error("linker missing at {0}")]
    MissingLinker(PathBuf),
    #[error("linker validation failed for {binary}: {source}")]
    Linker { binary: PathBuf, source: LinkerError },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn dummy_plan(require_linker: bool) -> EntryBundlePlan {
        EntryBundlePlan {
            display_name: "demo".into(),
            binary_source: PathBuf::from("/bin/echo"),
            binary_destination: PathBuf::from("payload/bin/demo"),
            linker_source: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            linker_destination: PathBuf::from("payload/lib64/ld-linux-x86-64.so.2"),
            library_dirs: vec![PathBuf::from("payload/lib64")],
            requires_linker: require_linker,
        }
    }

    #[test]
    fn missing_binary_is_error() {
        let validator = BundleValidator::new();
        let tmp = tempdir().unwrap();
        let result = validator.validate(tmp.path(), &[dummy_plan(true)]);
        assert!(matches!(result, Err(ValidationError::MissingBinary(_))));
    }

    #[test]
    fn static_entry_only_checks_binary() {
        let validator = BundleValidator::new();
        let tmp = tempdir().unwrap();
        let plan = dummy_plan(false);
        let binary_path = tmp.path().join(&plan.binary_destination);
        fs::create_dir_all(binary_path.parent().unwrap()).unwrap();
        fs::write(&binary_path, b"#!/bin/true\n").unwrap();
        assert!(validator.validate(tmp.path(), &[plan]).is_ok());
    }
}

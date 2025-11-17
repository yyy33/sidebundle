use std::fs;
use std::io::Write;
use std::path::Path;

use sidebundle_core::EntryBundlePlan;

use crate::PackagerError;

const LAUNCHER_BYTES: &[u8] = include_bytes!(env!("SIDEBUNDLE_LAUNCHER_BIN"));
const CONFIG_DIR: &str = "launchers";
const BINARY_NAME: &str = ".sidebundle-launcher";

pub fn write_launchers(bundle_root: &Path, plans: &[EntryBundlePlan]) -> Result<(), PackagerError> {
    let bin_dir = bundle_root.join("bin");
    fs::create_dir_all(&bin_dir).map_err(|source| PackagerError::Io {
        path: bin_dir.clone(),
        source,
    })?;
    let launcher_path = bin_dir.join(BINARY_NAME);
    fs::write(&launcher_path, LAUNCHER_BYTES).map_err(|source| PackagerError::Io {
        path: launcher_path.clone(),
        source,
    })?;
    set_exec_permissions(&launcher_path)?;

    let config_dir = bundle_root.join(CONFIG_DIR);
    fs::create_dir_all(&config_dir).map_err(|source| PackagerError::Io {
        path: config_dir.clone(),
        source,
    })?;

    for plan in plans {
        write_config(&config_dir, plan)?;
        link_entry(&bin_dir, plan)?;
    }
    Ok(())
}

fn write_config(dir: &Path, plan: &EntryBundlePlan) -> Result<(), PackagerError> {
    let config_path = dir.join(format!("{}.conf", plan.display_name));
    let mut file = fs::File::create(&config_path).map_err(|source| PackagerError::Io {
        path: config_path.clone(),
        source,
    })?;
    let mut content = String::new();
    content.push_str(&format!("dynamic={}\n", if plan.requires_linker { 1 } else { 0 }));
    content.push_str(&format!("binary={}\n", plan.binary_destination.display()));
    if plan.requires_linker {
        content.push_str(&format!("linker={}\n", plan.linker_destination.display()));
        let joined = plan
            .library_dirs
            .iter()
            .map(|dir| dir.display().to_string())
            .collect::<Vec<_>>()
            .join(":");
        content.push_str(&format!("library_paths={}\n", joined));
    }
    file.write_all(content.as_bytes()).map_err(|source| PackagerError::Io {
        path: config_path.clone(),
        source,
    })?;
    Ok(())
}

fn link_entry(bin_dir: &Path, plan: &EntryBundlePlan) -> Result<(), PackagerError> {
    let entry_path = bin_dir.join(&plan.display_name);
    if entry_path.exists() {
        fs::remove_file(&entry_path).map_err(|source| PackagerError::Io {
            path: entry_path.clone(),
            source,
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(Path::new(BINARY_NAME), &entry_path).map_err(|source| PackagerError::Io {
            path: entry_path.clone(),
            source,
        })?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        let target = bin_dir.join(BINARY_NAME);
        fs::copy(&target, &entry_path).map_err(|source| PackagerError::Io {
            path: entry_path.clone(),
            source,
        })?;
        set_exec_permissions(&entry_path)?;
        Ok(())
    }
}

fn set_exec_permissions(path: &Path) -> Result<(), PackagerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).map_err(|source| PackagerError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).map_err(|source| PackagerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

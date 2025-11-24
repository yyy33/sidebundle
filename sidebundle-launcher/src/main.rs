use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use sidebundle_core::RuntimeMetadata;
use std::collections::BTreeMap;
use std::env;
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("sidebundle launcher: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let exe_path = env::current_exe().context("failed to resolve launcher path")?;
    let launcher_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow!("launcher missing parent directory"))?;
    let bundle_root = launcher_dir
        .parent()
        .ok_or_else(|| anyhow!("launcher missing bundle root"))?;

    let invoked = env::args_os()
        .next()
        .ok_or_else(|| anyhow!("missing argv0"))?;
    let entry_name = Path::new(&invoked)
        .file_name()
        .ok_or_else(|| anyhow!("invalid launcher invocation"))?
        .to_string_lossy()
        .into_owned();

    let config = load_config(bundle_root, &entry_name)?;
    match config {
        LauncherConfig::Binary {
            dynamic,
            binary,
            linker,
            library_paths,
            metadata,
        } => {
            let entry_path = bundle_root.join(&binary);
            let argv = build_binary_argv(&entry_path)?;
            let env_block = build_env_block(bundle_root, &library_paths, metadata.as_ref())?;
            if !dynamic {
                exec_static(&entry_path, &argv, &env_block)?;
                unreachable!();
            }
            let linker = linker
                .as_ref()
                .map(|rel| bundle_root.join(rel))
                .ok_or_else(|| anyhow!("dynamic launcher missing linker path"))?;
            exec_dynamic(&linker, &entry_path, &argv, &env_block)?;
            unreachable!();
        }
        LauncherConfig::Script {
            dynamic,
            interpreter,
            script,
            args,
            linker,
            library_paths,
            metadata,
        } => {
            let interpreter_path = bundle_root.join(&interpreter);
            let script_path = bundle_root.join(&script);
            let argv = build_script_argv(&interpreter_path, &script_path, &args)?;
            let env_block = build_env_block(bundle_root, &library_paths, metadata.as_ref())?;
            if !dynamic {
                exec_static(&interpreter_path, &argv, &env_block)?;
                unreachable!();
            }
            let linker = linker
                .as_ref()
                .map(|rel| bundle_root.join(rel))
                .ok_or_else(|| anyhow!("dynamic launcher missing linker path"))?;
            exec_dynamic(&linker, &interpreter_path, &argv, &env_block)?;
            unreachable!();
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LauncherConfig {
    Binary {
        dynamic: bool,
        binary: PathBuf,
        linker: Option<PathBuf>,
        library_paths: Vec<PathBuf>,
        metadata: Option<RuntimeMetadata>,
    },
    Script {
        dynamic: bool,
        interpreter: PathBuf,
        script: PathBuf,
        args: Vec<String>,
        linker: Option<PathBuf>,
        library_paths: Vec<PathBuf>,
        metadata: Option<RuntimeMetadata>,
    },
}

fn load_config(bundle_root: &Path, entry_name: &str) -> Result<LauncherConfig> {
    let path = bundle_root
        .join("launchers")
        .join(format!("{entry_name}.json"));
    let data = fs::read(&path)
        .with_context(|| format!("failed to read launcher config {}", path.display()))?;
    serde_json::from_slice(&data)
        .with_context(|| format!("invalid launcher config {}", path.display()))
}

fn build_binary_argv(entry: &Path) -> Result<Vec<CString>> {
    let mut argv = Vec::new();
    argv.push(os_to_cstring(entry.as_os_str())?);
    for arg in env::args_os().skip(1) {
        argv.push(os_to_cstring(&arg)?);
    }
    Ok(argv)
}

fn build_script_argv(interpreter: &Path, script: &Path, args: &[String]) -> Result<Vec<CString>> {
    let mut argv = Vec::new();
    argv.push(os_to_cstring(interpreter.as_os_str())?);
    for arg in args {
        argv.push(CString::new(arg.as_bytes()).map_err(|err| anyhow!("invalid arg: {err}"))?);
    }
    argv.push(os_to_cstring(script.as_os_str())?);
    for arg in env::args_os().skip(1) {
        argv.push(os_to_cstring(&arg)?);
    }
    Ok(argv)
}

fn build_env_block(
    bundle_root: &Path,
    library_paths: &[PathBuf],
    metadata: Option<&RuntimeMetadata>,
) -> Result<Vec<CString>> {
    let mut env_map: BTreeMap<String, String> = metadata
        .cloned()
        .map(|meta| meta.env)
        .unwrap_or_else(|| env::vars().collect());
    env_map.insert(
        "SIDEBUNDLE_ROOT".into(),
        bundle_root.to_string_lossy().into_owned(),
    );

    if let Some(java_home) = env_map.get("JAVA_HOME").cloned() {
        if java_home.starts_with('/') {
            let mut mapped = bundle_root.to_path_buf();
            mapped.push("payload");
            mapped.push(java_home.trim_start_matches('/'));
            env_map.insert("JAVA_HOME".into(), mapped.to_string_lossy().into_owned());
        }
    }

    let mut mapped_path_entries: Vec<String> = Vec::new();
    if let Some(path) = env_map.get("PATH").cloned() {
        mapped_path_entries = remap_path_entries(bundle_root, &path);
        if !mapped_path_entries.is_empty() {
            let mut combined = mapped_path_entries.join(":");
            if !path.is_empty() {
                combined.push(':');
                combined.push_str(&path);
            }
            env_map.insert("PATH".into(), combined);
        }
    }

    if !library_paths.is_empty() {
        let mut entries: Vec<String> = library_paths
            .iter()
            .map(|path| bundle_root.join(path).to_string_lossy().into_owned())
            .collect();
        if let Some(java_home) = env_map.get("JAVA_HOME") {
            let jh = Path::new(java_home);
            entries.push(jh.join("lib").to_string_lossy().into_owned());
            entries.push(jh.join("lib/server").to_string_lossy().into_owned());
        }
        // Heuristic: for each PATH bin entry, also add sibling lib directories to help JVM loads.
        for bin in &mapped_path_entries {
            let bin_path = Path::new(bin);
            if let Some(parent) = bin_path.parent() {
                entries.push(parent.join("lib").to_string_lossy().into_owned());
                entries.push(parent.join("lib/server").to_string_lossy().into_owned());
            }
        }
        dedup_strings(&mut entries);
        let joined = entries.join(":");
        env_map.insert("LD_LIBRARY_PATH".into(), joined);
    }

    let mut block = Vec::new();
    for (key, value) in env_map {
        let mut pair = key;
        pair.push('=');
        pair.push_str(&value);
        block.push(CString::new(pair).map_err(|err| anyhow!("invalid env: {err}"))?);
    }
    Ok(block)
}

fn remap_path_entries(bundle_root: &Path, path: &str) -> Vec<String> {
    path.split(':')
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| {
            let stripped = p.strip_prefix("/").unwrap_or(&p);
            bundle_root
                .join("payload")
                .join(stripped)
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|v| seen.insert(v.clone()));
}

fn os_to_cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|err| anyhow!("invalid string: {err}"))
}

fn exec_static(entry: &Path, argv: &[CString], envp: &[CString]) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;

    let entry_cstr =
        CString::new(entry.as_os_str().as_bytes()).map_err(|err| anyhow!("invalid path: {err}"))?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = envp.iter().map(|env| env.as_ptr()).collect();
    env_ptrs.push(ptr::null());

    unsafe {
        libc::execve(entry_cstr.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    Err(std::io::Error::last_os_error())
        .with_context(|| format!("execve failed for {}", entry.display()))
}

fn exec_dynamic(linker: &Path, entry: &Path, argv: &[CString], envp: &[CString]) -> Result<()> {
    use std::ptr;

    let linker_cstr = os_to_cstring(linker.as_os_str())?;
    let entry_cstr = os_to_cstring(entry.as_os_str())?;

    let mut argv_ptrs: Vec<*const libc::c_char> = Vec::with_capacity(argv.len() + 2);
    argv_ptrs.push(linker_cstr.as_ptr());
    argv_ptrs.push(entry_cstr.as_ptr());
    for arg in argv.iter().skip(1) {
        argv_ptrs.push(arg.as_ptr());
    }
    argv_ptrs.push(ptr::null());

    let mut env_ptrs: Vec<*const libc::c_char> = envp.iter().map(|env| env.as_ptr()).collect();
    env_ptrs.push(ptr::null());

    unsafe {
        libc::execve(linker_cstr.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    Err(std::io::Error::last_os_error()).with_context(|| {
        format!(
            "execve failed for linker {} (entry {})",
            linker.display(),
            entry.display()
        )
    })
}

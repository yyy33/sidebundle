use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::os::unix::process::CommandExt;

const NOVDSO_REL_PATH: &str = "payload/lib/.sidebundle-novdso.so";

fn main() {
    if let Err(err) = run() {
        eprintln!("sidebundle launcher: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let exe_path = env::current_exe().map_err(|err| format!("failed to resolve launcher path: {err}"))?;
    let launcher_dir = exe_path
        .parent()
        .ok_or_else(|| "launcher missing parent directory".to_string())?;
    let bundle_root = launcher_dir
        .parent()
        .ok_or_else(|| "launcher missing bundle root".to_string())?;

    let invoked = env::args()
        .next()
        .ok_or_else(|| "missing argv0".to_string())?;
    let name = Path::new(&invoked)
        .file_name()
        .ok_or_else(|| "invalid launcher invocation".to_string())?
        .to_string_lossy()
        .into_owned();

    let config_path = bundle_root.join("launchers").join(format!("{name}.conf"));
    let config = fs::read_to_string(&config_path)
        .map_err(|err| format!("failed to read launcher config {}: {err}", config_path.display()))?;
    let launch_cfg = LaunchConfig::parse(&config)
        .map_err(|err| format!("invalid launcher config {}: {err}", config_path.display()))?;

    let entry = bundle_root.join(&launch_cfg.binary);
    let mut args: Vec<String> = Vec::new();
    args.push(entry.to_string_lossy().into_owned());
    args.extend(env::args().skip(1));

    env::set_var(
        "SIDEBUNDLE_ROOT",
        bundle_root.to_string_lossy().to_string(),
    );
    apply_assume_kernel();

    let extra_args: Vec<String> = env::args().skip(1).collect();

    if launch_cfg.dynamic {
        let linker_rel = launch_cfg
            .linker
            .ok_or_else(|| "dynamic launcher missing linker".to_string())?;
        let linker = bundle_root.join(&linker_rel);
        let hwcaps_enabled = hwcaps_enabled();
        apply_hwcaps_policy(hwcaps_enabled);
        let search_paths =
            build_library_paths(bundle_root, &launch_cfg.library_paths, hwcaps_enabled);
        ensure_bundle_dependencies(&linker, &entry, &search_paths, bundle_root)?;
        run_dynamic_entry(&linker, &entry, &extra_args, &search_paths, bundle_root);
    } else {
        let mut cmd = Command::new(entry);
        cmd.args(extra_args);
        let err = cmd.exec();
        Err(format!("failed to exec entry: {err}"))
    }
}

struct LaunchConfig {
    dynamic: bool,
    linker: Option<PathBuf>,
    binary: PathBuf,
    library_paths: Vec<PathBuf>,
}

impl LaunchConfig {
    fn parse(contents: &str) -> Result<Self, String> {
        let mut cfg = LaunchConfig {
            dynamic: false,
            linker: None,
            binary: PathBuf::new(),
            library_paths: Vec::new(),
        };
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, '=');
            let key = parts
                .next()
                .ok_or_else(|| "invalid config line".to_string())?
                .trim();
            let value = parts
                .next()
                .ok_or_else(|| "invalid config line".to_string())?
                .trim();
            match key {
                "dynamic" => {
                    cfg.dynamic = value == "1";
                }
                "linker" => {
                    if !value.is_empty() {
                        cfg.linker = Some(PathBuf::from(value));
                    }
                }
                "binary" => {
                    cfg.binary = PathBuf::from(value);
                }
                "library_paths" => {
                    if !value.is_empty() {
                        cfg.library_paths = value
                            .split(':')
                            .map(|segment| segment.trim())
                            .filter(|segment| !segment.is_empty())
                            .map(PathBuf::from)
                            .collect();
                    }
                }
                _ => {}
            }
        }
        if cfg.binary.as_os_str().is_empty() {
            return Err("binary path missing".into());
        }
        Ok(cfg)
    }
}

fn hwcaps_enabled() -> bool {
    env::var("SB_ENABLE_HWCAPS")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false)
}

fn apply_hwcaps_policy(enabled: bool) {
    if enabled {
        return;
    }
    const DISABLE_TUNABLE: &str = "glibc.cpu.hwcaps=-x86-64-v4,-x86-64-v3,-x86-64-v2";
    match env::var("GLIBC_TUNABLES") {
        Ok(existing) => {
            if existing.contains("glibc.cpu.hwcaps") {
                return;
            }
            let mut combined = existing;
            if !combined.is_empty() {
                combined.push(':');
            }
            combined.push_str(DISABLE_TUNABLE);
            env::set_var("GLIBC_TUNABLES", combined);
        }
        Err(_) => {
            env::set_var("GLIBC_TUNABLES", DISABLE_TUNABLE);
        }
    }
}

fn apply_assume_kernel() {
    if env::var("LD_ASSUME_KERNEL").is_ok() {
        return;
    }
    if let Ok(custom) = env::var("SIDEBUNDLE_ASSUME_KERNEL") {
        if !custom.trim().is_empty() {
            env::set_var("LD_ASSUME_KERNEL", custom);
            return;
        }
    }
    env::set_var("LD_ASSUME_KERNEL", "4.14.0");
}

fn build_library_paths(
    bundle_root: &Path,
    raw_paths: &[PathBuf],
    include_hwcaps: bool,
) -> Vec<String> {
    let mut baseline = Vec::new();
    let mut hwcaps = Vec::new();
    for rel in raw_paths {
        let absolute = bundle_root.join(rel).to_string_lossy().into_owned();
        if rel
            .to_string_lossy()
            .contains("glibc-hwcaps")
        {
            hwcaps.push(absolute);
        } else {
            baseline.push(absolute);
        }
    }
    if include_hwcaps {
        baseline.extend(hwcaps);
    }
    baseline
}

fn ensure_bundle_dependencies(
    linker: &Path,
    entry: &Path,
    search_paths: &[String],
    bundle_root: &Path,
) -> Result<(), String> {
    let mut cmd = Command::new(linker);
    if !search_paths.is_empty() {
        cmd.arg("--library-path");
        cmd.arg(search_paths.join(":"));
    }
    cmd.arg("--list");
    cmd.arg(entry);
    let output = cmd
        .output()
        .map_err(|err| format!("failed to invoke linker --list: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("linker --list failed: {stderr}"));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(dep) = parse_dependency_path(line) {
            if dep.starts_with("linux-vdso") || dep.starts_with("linux-gate") {
                continue;
            }
            if dep.contains("not found") || dep == "not" {
                return Err(format!("dependency {line} not resolved within bundle"));
            }
            if !path_within_bundle(bundle_root, dep) {
                return Err(format!(
                    "dependency {dep} resolved outside bundle root {}",
                    bundle_root.display()
                ));
            }
        }
    }
    Ok(())
}

fn run_dynamic_entry(
    linker: &Path,
    entry: &Path,
    extra_args: &[String],
    search_paths: &[String],
    bundle_root: &Path,
) -> ! {
    let search_arg = if search_paths.is_empty() {
        None
    } else {
        Some(search_paths.join(":"))
    };
    let shim_path = bundle_root.join(NOVDSO_REL_PATH);
    let shim_arg = shim_path.to_string_lossy().into_owned();
    let has_shim = shim_path.exists();
    let strategy = vdso_strategy();
    let mut attempts = Vec::new();
    match strategy {
        VdsoStrategy::ForceShim if has_shim => attempts.push(true),
        VdsoStrategy::ForceShim => attempts.push(false),
        VdsoStrategy::Disabled => attempts.push(false),
        VdsoStrategy::Default => {
            attempts.push(false);
            if has_shim {
                attempts.push(true);
            }
        }
    }
    if attempts.is_empty() {
        attempts.push(false);
    }
    for use_shim in attempts {
        let mut cmd = Command::new(linker);
        if let Some(arg) = &search_arg {
            cmd.arg("--library-path");
            cmd.arg(arg);
        }
        if use_shim {
            cmd.env("LD_PRELOAD", &shim_arg);
        } else {
            cmd.env_remove("LD_PRELOAD");
        }
        cmd.arg(entry);
        cmd.args(extra_args);
        let status = match cmd.status() {
            Ok(status) => status,
            Err(err) => {
                eprintln!("sidebundle launcher: failed to spawn linker: {err}");
                std::process::exit(1);
            }
        };
        if status.success() {
            std::process::exit(0);
        }
        let fallback_possible =
            matches!(strategy, VdsoStrategy::Default) && has_shim && !use_shim;
        if fallback_possible {
            eprintln!(
                "sidebundle launcher: entry exited with status {:?}; retrying with SB_DISABLE_VDSO shim",
                status.code()
            );
            continue;
        }
        exit_with_status(status);
    }
    std::process::exit(1);
}

fn parse_dependency_path(line: &str) -> Option<&str> {
    let idx = line.find("=>")?;
    let after = line[idx + 2..].trim();
    if after.is_empty() {
        return None;
    }
    let path = after.split_whitespace().next()?;
    if path == "not" {
        return Some("not found");
    }
    Some(path)
}

#[derive(Clone, Copy)]
enum VdsoStrategy {
    Default,
    ForceShim,
    Disabled,
}

fn vdso_strategy() -> VdsoStrategy {
    match env::var("SB_DISABLE_VDSO") {
        Ok(value) => match parse_bool(&value) {
            Some(true) => VdsoStrategy::ForceShim,
            Some(false) => VdsoStrategy::Disabled,
            None => VdsoStrategy::Default,
        },
        Err(_) => VdsoStrategy::Default,
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn exit_with_status(status: ExitStatus) -> ! {
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            std::process::exit(128 + signal);
        }
    }
    std::process::exit(1);
}

fn path_within_bundle(bundle_root: &Path, candidate: &str) -> bool {
    if candidate.is_empty() {
        return true;
    }
    let path = Path::new(candidate);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        bundle_root.join(path)
    };
    match resolved.canonicalize() {
        Ok(real) => real.starts_with(bundle_root),
        Err(_) => resolved.starts_with(bundle_root),
    }
}

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::unix::process::CommandExt;

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

    if launch_cfg.dynamic {
        let linker_rel = launch_cfg
            .linker
            .ok_or_else(|| "dynamic launcher missing linker".to_string())?;
        let linker = bundle_root.join(&linker_rel);
        let search_paths: Vec<String> = launch_cfg
            .library_paths
            .iter()
            .map(|p| bundle_root.join(p).to_string_lossy().into_owned())
            .collect();
        let mut cmd = Command::new(linker);
        if !search_paths.is_empty() {
            cmd.arg("--library-path");
            cmd.arg(search_paths.join(":"));
        }
        cmd.arg(entry);
        cmd.args(env::args().skip(1));
        let err = cmd.exec();
        Err(format!("failed to exec linker: {err}"))
    } else {
        let mut cmd = Command::new(entry);
        cmd.args(env::args().skip(1));
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

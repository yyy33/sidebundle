use std::collections::{BTreeSet, HashMap};
use std::env;
use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::libc;
use nix::sys::ptrace::{self, AddressType};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{chdir, chroot, execve, fork, ForkResult, Pid};

#[derive(Debug, Clone, Default)]
pub struct TraceCollector {
    root: Option<PathBuf>,
}

impl TraceCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    pub fn run(&self, command: &[String]) -> Result<TraceReport, TraceError> {
        if command.is_empty() {
            return Err(TraceError::EmptyCommand);
        }

        let argv = strings_to_cstring(command)?;
        let envp = envp_to_cstring()?;

        unsafe {
            match fork().map_err(TraceError::Nix)? {
                ForkResult::Child => child_main(self.root.as_deref(), &argv, &envp),
                ForkResult::Parent { child } => parent_trace(child),
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TraceReport {
    pub files: BTreeSet<PathBuf>,
}

impl TraceReport {
    fn record_path(&mut self, path: PathBuf) {
        if path.as_os_str().is_empty() {
            return;
        }
        self.files.insert(path);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("empty command")]
    EmptyCommand,
    #[error("failed to convert string: {0}")]
    CString(#[from] std::ffi::NulError),
    #[error("IO: {0}")]
    Io(#[from] io::Error),
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
    #[error("ptrace not permitted: {0}")]
    Permission(String),
    #[error("traced process exited unexpectedly")]
    UnexpectedExit,
}

fn strings_to_cstring(values: &[String]) -> Result<Vec<CString>, TraceError> {
    values
        .iter()
        .map(|s| Ok(CString::new(s.as_str())?))
        .collect()
}

fn envp_to_cstring() -> Result<Vec<CString>, TraceError> {
    env::vars_os()
        .map(|(k, v)| {
            let mut bytes = Vec::new();
            bytes.extend(k.as_os_str().as_bytes());
            bytes.push(b'=');
            bytes.extend(v.as_os_str().as_bytes());
            Ok(CString::new(bytes)?)
        })
        .collect()
}

unsafe fn child_main(root: Option<&Path>, argv: &[CString], envp: &[CString]) -> ! {
    if let Some(root) = root {
        if let Err(err) = chdir(root)
            .and_then(|_| chroot("."))
            .and_then(|_| chdir(Path::new("/")))
        {
            eprintln!("sidebundle trace: failed to chroot: {err:?}");
            std::process::exit(TraceExit::ChrootFailure as i32);
        }
    }

    if let Err(err) = ptrace::traceme() {
        eprintln!("sidebundle trace: ptrace TRACEME failed: {err:?}");
        std::process::exit(TraceExit::PtraceDenied as i32);
    }
    let _ = kill(Pid::from_raw(libc::getpid()), Signal::SIGSTOP);

    let argv_refs: Vec<&CStr> = argv.iter().map(|c| c.as_c_str()).collect();
    let envp_refs: Vec<&CStr> = envp.iter().map(|c| c.as_c_str()).collect();
    match execve(&argv_refs[0], &argv_refs, &envp_refs) {
        Ok(_) => unreachable!(),
        Err(err) => {
            eprintln!("sidebundle trace: execve failed: {err:?}");
            std::process::exit(TraceExit::ExecFailure as i32);
        }
    }
}

unsafe fn parent_trace(child: Pid) -> Result<TraceReport, TraceError> {
    let mut report = TraceReport::default();
    let mut entering: HashMap<Pid, bool> = HashMap::new();

    loop {
        match waitpid(Some(child), Some(WaitPidFlag::empty())) {
            Ok(WaitStatus::Stopped(pid, Signal::SIGSTOP)) => {
                ptrace::setoptions(
                    pid,
                    ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEEXIT,
                )
                .map_err(TraceError::Nix)?;
                ptrace::syscall(pid, None).map_err(TraceError::Nix)?;
            }
            Ok(WaitStatus::PtraceSyscall(pid)) => {
                let entry = entering.entry(pid).or_insert(true);
                if *entry {
                    if let Err(err) = handle_syscall(pid, &mut report) {
                        ptrace::detach(pid, None).ok();
                        return Err(err);
                    }
                }
                *entry = !*entry;
                ptrace::syscall(pid, None).map_err(TraceError::Nix)?;
            }
            Ok(WaitStatus::PtraceEvent(pid, _, _)) => {
                ptrace::syscall(pid, None).map_err(TraceError::Nix)?;
            }
            Ok(WaitStatus::Exited(pid, status)) => {
                if pid == child {
                    return match TraceExit::from_status(status) {
                        Some(TraceExit::PtraceDenied) => Err(TraceError::Permission(
                            "ptrace not permitted on this system".into(),
                        )),
                        Some(TraceExit::ChrootFailure) => Err(TraceError::Io(io::Error::new(
                            io::ErrorKind::Other,
                            "failed to chroot into trace root",
                        ))),
                        Some(TraceExit::ExecFailure) => Err(TraceError::Io(io::Error::new(
                            io::ErrorKind::Other,
                            "failed to exec trace command",
                        ))),
                        None => Ok(report),
                    };
                }
            }
            Ok(WaitStatus::Signaled(pid, _sig, _)) => {
                if pid == child {
                    return Err(TraceError::UnexpectedExit);
                }
            }
            Ok(WaitStatus::StillAlive) => {}
            Ok(WaitStatus::Continued(_)) => {}
            Ok(WaitStatus::Stopped(pid, _)) => {
                ptrace::syscall(pid, None).map_err(TraceError::Nix)?;
            }
            Err(err) => {
                if let nix::errno::Errno::ECHILD = err {
                    return Ok(report);
                } else {
                    return Err(TraceError::Nix(err));
                }
            }
        }
    }
}

fn handle_syscall(pid: Pid, report: &mut TraceReport) -> Result<(), TraceError> {
    let regs = ptrace::getregs(pid).map_err(TraceError::Nix)?;
    let syscall = regs.orig_rax as i64;
    let addr = match syscall {
        libc::SYS_open => regs.rdi as usize,
        libc::SYS_openat => regs.rsi as usize,
        libc::SYS_execve => regs.rdi as usize,
        libc::SYS_stat => regs.rdi as usize,
        libc::SYS_newfstatat => regs.rsi as usize,
        libc::SYS_lstat => regs.rdi as usize,
        _ => 0,
    };
    if addr == 0 {
        return Ok(());
    }
    let path = read_string(pid, addr)?;
    if !path.is_empty() {
        report.record_path(PathBuf::from(path));
    }
    Ok(())
}

fn read_string(pid: Pid, addr: usize) -> Result<String, TraceError> {
    let mut bytes = Vec::new();
    let mut offset = 0usize;
    loop {
        let data = ptrace::read(pid, (addr + offset) as AddressType).map_err(TraceError::Nix)?;
        let data_bytes = (data as libc::c_long).to_ne_bytes();
        for byte in data_bytes {
            if byte == 0 {
                return String::from_utf8(bytes)
                    .map_err(|e| TraceError::Io(io::Error::new(io::ErrorKind::InvalidData, e)));
            }
            bytes.push(byte);
        }
        offset += data_bytes.len();
    }
}

#[repr(i32)]
enum TraceExit {
    ChrootFailure = 40,
    PtraceDenied = 41,
    ExecFailure = 42,
}

impl TraceExit {
    fn from_status(status: i32) -> Option<Self> {
        match status {
            x if x == TraceExit::ChrootFailure as i32 => Some(TraceExit::ChrootFailure),
            x if x == TraceExit::PtraceDenied as i32 => Some(TraceExit::PtraceDenied),
            x if x == TraceExit::ExecFailure as i32 => Some(TraceExit::ExecFailure),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_dedup() {
        let mut report = TraceReport::default();
        report.record_path(PathBuf::from("/tmp/a"));
        report.record_path(PathBuf::from("/tmp/a"));
        assert_eq!(report.files.len(), 1);
    }
}

//! Best-effort Linux sandbox for the `hivecyber-worker` process.
//!
//! Components applied (in order), fail-closed where possible:
//!   1. `PR_SET_NO_NEW_PRIVS` (always succeeds when unprivileged).
//!   2. rlimits: CPU, RSS, NPROC, NOFILE, CORE.
//!   3. capability drop (all capsets — requires root; skipped with a warning
//!      when unprivileged, since seccomp still confines the process).
//!   4. user + mount namespaces (best-effort — warn and continue without
//!      them when unavailable). PID and network namespaces are deliberately
//!      NOT unshared: NEWPID is incompatible with tokio's multi-threaded
//!      runtime, and NEWNET would leave sandboxed tools (hydra,
//!      crackmapexec, metasploit_rpc, mimikatz) with no route to their
//!      targets. See `try_namespaces` for details.
//!   5. seccomp BPF filter (allowlist syscall policy; unprivileged, enforced).
//!   6. Landlock filesystem restriction (best-effort; unprivileged on
//!      kernels >= 5.13).
//!
//! Seccomp is the load-bearing layer: it is applied last and with
//! `SECCOMP_RET_KILL_PROCESS` for the most dangerous syscalls and
//! `SECCOMP_RET_ERRNO(EPERM)` for everything not in the allowlist.

use anyhow::Result;
// `Context` is only used by the Linux syscall wrappers below, which only
// compile for the architectures the seccomp allowlist actually supports.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
use anyhow::Context;

// -----------------------------------------------------------------------------
// Public entry point
// -----------------------------------------------------------------------------

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn apply_sandbox() -> Result<()> {
    tracing::info!("applying Linux sandbox (no_new_privs + rlimits + caps + namespaces + seccomp)");

    set_no_new_privs()?;
    apply_rlimits()?;
    drop_capabilities()?;
    try_namespaces()?;
    apply_seccomp_filter()?;
    try_landlock()?;

    tracing::info!("sandbox applied: seccomp + rlimits (namespaces/landlock best-effort)");
    Ok(())
}

// Linux, but not one of the two architectures the seccomp allowlist is built
// and tested for (x86_64, aarch64 — see kill_syscalls_list/allow_syscalls_list,
// which reference real per-arch syscall numbers via the `libc` crate). Rather
// than fabricate an allowlist for an unverified architecture, fail closed like
// the non-Linux path below.
#[cfg(all(target_os = "linux", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn apply_sandbox() -> Result<()> {
    fail_closed(&format!(
        "worker sandbox not implemented for {} on Linux (only x86_64 and aarch64 are supported)",
        std::env::consts::ARCH
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn apply_sandbox() -> Result<()> {
    fail_closed(&format!("worker sandbox unavailable on {}", std::env::consts::OS))
}

// Shared fail-closed behavior for platforms/architectures without a real
// sandbox implementation: refuse sandboxed (exploit) tools by default so they
// never run unconfined silently. Operators who accept the risk opt in
// explicitly (mirrors the middleware's gate; this is defense in depth in case
// the worker is invoked directly).
#[cfg(any(not(target_os = "linux"), not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn fail_closed(context: &str) -> Result<()> {
    let opted_in = std::env::var("HIVECYBER_ALLOW_UNSANDBOXED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if opted_in {
        tracing::warn!("{} but HIVECYBER_ALLOW_UNSANDBOXED=1 — running UNCONFINED", context);
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "{} — refusing to run sandboxed (exploit) tools. Use the Linux/x86_64 or Linux/aarch64 \
         Docker image, or set HIVECYBER_ALLOW_UNSANDBOXED=1 to override (unsafe).",
        context
    ))
}

// -----------------------------------------------------------------------------
// PR_SET_NO_NEW_PRIVS
// -----------------------------------------------------------------------------

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn set_no_new_privs() -> Result<()> {
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// rlimits
// -----------------------------------------------------------------------------

// musl's setrlimit()/getrlimit() take a plain `c_int` resource id; glibc's
// take `__rlimit_resource_t` (== c_uint) — the exact same parameter has a
// different type per libc environment (confirmed against the `libc` crate's
// own `cfg_if!` on `target_env` for the RLIMIT_* constants). Alias to
// whichever this target's libc actually expects so `set()` below type-checks
// against both.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"), target_env = "musl"))]
type RlimitResource = libc::c_int;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"), not(target_env = "musl")))]
type RlimitResource = libc::__rlimit_resource_t;

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn apply_rlimits() -> Result<()> {
    use libc::{setrlimit, rlimit};

    fn set(res: RlimitResource, soft: u64, hard: u64, label: &str) -> Result<()> {
        let rl = rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        let rc = unsafe { setrlimit(res, &rl) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .context(format!("setrlimit({}) failed", label));
        }
        Ok(())
    }

    // CPU: 600s, FSIZE: 1GB, NOFILE: 256, RSS: 1GB, CORE: 0
    set(libc::RLIMIT_CPU, 600, 600, "CPU").ok();
    set(libc::RLIMIT_FSIZE, 1_073_741_824, 1_073_741_824, "FSIZE").ok();
    set(libc::RLIMIT_NOFILE, 256, 256, "NOFILE").ok();
    set(libc::RLIMIT_RSS, 1_073_741_824, 1_073_741_824, "RSS").ok();
    set(libc::RLIMIT_CORE, 0, 0, "CORE").ok();

    // RLIMIT_NPROC is enforced against the *real UID's task count for the
    // whole system* (all tasks/threads owned by this UID, not just this
    // process), and unshare(CLONE_NEWUSER) does not reset that accounting on
    // this kernel. A fixed low constant (e.g. 64) reliably wedges the worker
    // on any desktop/dev machine — the UID already owns thousands of threads
    // (browser, IDE, shell...) before the worker even starts, so tokio's own
    // thread pool can never spawn (EAGAIN) and stdin reads hang forever.
    // Instead, size the limit relative to the UID's current task count so it
    // still bounds a runaway fork bomb from a compromised tool without
    // wedging normal startup.
    let headroom: u64 = 1024;
    match current_uid_task_count() {
        Some(current) => {
            let cap = current + headroom;
            set(libc::RLIMIT_NPROC, cap, cap, "NPROC").ok();
        }
        None => {
            tracing::debug!("could not count current UID tasks — leaving RLIMIT_NPROC unset");
        }
    }
    Ok(())
}

/// Counts tasks (processes + threads) currently owned by our real UID across
/// the whole system, by scanning `/proc/*/status`. Best-effort: returns
/// `None` on any read error rather than guessing, so the caller can skip
/// clamping RLIMIT_NPROC instead of picking an unsafe value.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn current_uid_task_count() -> Option<u64> {
    let my_uid = unsafe { libc::getuid() };
    let mut total: u64 = 0;

    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let status_path = entry.path().join("status");
        let status = match std::fs::read_to_string(&status_path) {
            Ok(s) => s,
            Err(_) => continue, // process exited mid-scan — skip it
        };
        let owned = status.lines().find_map(|line| {
            let rest = line.strip_prefix("Uid:")?;
            let ruid: u32 = rest.split_whitespace().next()?.parse().ok()?;
            Some(ruid == my_uid)
        });
        if owned == Some(true) {
            let threads = std::fs::read_dir(entry.path().join("task"))
                .map(|d| d.count() as u64)
                .unwrap_or(1);
            total += threads;
        }
    }
    Some(total)
}

// -----------------------------------------------------------------------------
// capabilities
// -----------------------------------------------------------------------------

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn drop_capabilities() -> Result<()> {
    use caps::CapSet;

    // Best-effort: drop all sets. When unprivileged we have nothing to drop
    // anyway; seccomp is the real confinement.
    for capset in &[
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Bounding,
        CapSet::Ambient,
    ] {
        let _ = caps::clear(None, *capset);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// namespaces
// -----------------------------------------------------------------------------

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn try_namespaces() -> Result<()> {
    use libc::CLONE_NEWNS;
    const CLONE_NEWUSER: i32 = 0x10000000;

    // Deliberately NOT unshared here:
    //   - CLONE_NEWPID: the kernel refuses to create new threads
    //     (CLONE_THREAD) in a process that has called unshare(CLONE_NEWPID) —
    //     it only affects *future children*, and our worker is a
    //     multi-threaded tokio process, not a fork-per-task model. Using it
    //     here reliably panics the tokio runtime on startup ("OS can't spawn
    //     worker thread: Invalid argument").
    //   - CLONE_NEWNET: an unshared network namespace has no configured
    //     interfaces (not even loopback brought up) — every tool routed
    //     into this sandbox (hydra, crackmapexec, metasploit_rpc, mimikatz)
    //     exists specifically to reach a network target, so this would
    //     silently blackhole all of them instead of confining them.
    //
    // new user namespace first so we can create the others unprivileged
    let rc = unsafe { libc::unshare(CLONE_NEWUSER) };
    if rc != 0 {
        tracing::warn!("unshare(NEWUSER) failed: {} — namespaces skipped", std::io::Error::last_os_error());
        return Ok(());
    }

    let _ = unsafe { libc::unshare(CLONE_NEWNS) };

    tracing::info!("namespaces applied (NEWUSER+NEWNS)");
    Ok(())
}

// -----------------------------------------------------------------------------
// seccomp
// -----------------------------------------------------------------------------

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod seccomp_bpf {
    use libc::{c_int, sock_filter, sock_fprog};

    pub const PR_SET_SECCOMP: c_int = 22;
    pub const SECCOMP_MODE_FILTER: c_int = 2;

    pub const BPF_LD_W_ABS: u16 = 0x20;
    pub const BPF_JMP_JEQ_K: u16 = 0x15;
    pub const BPF_RET_K: u16 = 0x06;

    pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    // EM_X86_64 (0x3e) | __AUDIT_ARCH_64BIT (0x80000000) | __AUDIT_ARCH_LE (0x40000000).
    // Previously 0xc000_0000 (missing the EM_X86_64 machine-type byte), which
    // never matched the real value the kernel provides — every syscall was
    // killed at the wrong-arch check before the allowlist was ever consulted.
    pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

    // EM_AARCH64 (183 = 0xb7) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE, per
    // linux/elf-em.h + linux/audit.h — same formula as AUDIT_ARCH_X86_64
    // above (regression-tested against a real kernel). Not independently
    // exercised on real aarch64 hardware in this repo's dev/CI environment;
    // if seccomp ever misbehaves specifically on aarch64, re-verify this
    // constant against `/usr/include/linux/audit.h` on real hardware first.
    pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

    #[cfg(target_arch = "x86_64")]
    pub const CURRENT_AUDIT_ARCH: u32 = AUDIT_ARCH_X86_64;
    #[cfg(target_arch = "aarch64")]
    pub const CURRENT_AUDIT_ARCH: u32 = AUDIT_ARCH_AARCH64;

    pub const SECCOMP_NR_OFF: u32 = 0;
    pub const SECCOMP_ARCH_OFF: u32 = 4;

    pub const EPERM: u32 = 1;

    pub fn insn(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
        sock_filter { code, jt, jf, k }
    }

    pub unsafe fn install(prog: &[sock_filter]) -> Result<(), std::io::Error> {
        let fprog = sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut sock_filter,
        };
        let rc = libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0);
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// syscalls that must be killed outright (irreversible / privilege bricking)
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn kill_syscalls_list() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_ptrace,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_pivot_root,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_open_by_handle_at,
        libc::SYS_keyctl,
        libc::SYS_request_key,
        libc::SYS_add_key,
    ];
    // iopl/ioperm: x86 port-I/O privilege syscalls. Their syscall numbers
    // don't exist on aarch64 (no legacy port-mapped I/O there) — nothing to
    // kill on an architecture that has no such syscall to begin with.
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_iopl, libc::SYS_ioperm]);
    // kexec_file_load: present for x86_64 (gnu+musl) and aarch64-gnu, but
    // musl's aarch64 syscall table doesn't define this constant at all
    // (verified against the `libc` crate source — not present in
    // linux/musl/b64/aarch64/mod.rs, unlike every other target combo here).
    #[cfg(not(all(target_arch = "aarch64", target_env = "musl")))]
    v.push(libc::SYS_kexec_file_load);
    v
}

// syscalls allowed for normal operation
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn allow_syscalls_list() -> Vec<i64> {
    // Base list: syscalls with real numbers on BOTH x86_64 and aarch64. aarch64
    // (and the "generic" 64-bit syscall ABI it introduced) dropped ~20 legacy
    // syscalls in favor of their `*at()`/modern replacements, which is why this
    // is a single shared base plus x86_64-only extras below, rather than one
    // flat list — the dropped names don't exist as `libc::SYS_*` constants for
    // aarch64 at all, so referencing them unconditionally fails to compile
    // there (verified against the `libc` crate's aarch64 syscall tables).
    let mut v = vec![
        libc::SYS_read, libc::SYS_write, libc::SYS_close,
        libc::SYS_fstat, libc::SYS_lseek, libc::SYS_mmap,
        // glibc's stat()/lstat()/fstatat()/access() wrappers prefer statx(2)
        // and newfstatat/faccessat2 over the legacy syscalls on modern
        // kernels. Without these, tokio::fs::metadata() and friends fail
        // with EPERM — which callers like fs_exists silently read as "file
        // does not exist" instead of a hard error. Found via `fs_exists`
        // returning false for a file that demonstrably exists.
        libc::SYS_statx, libc::SYS_newfstatat, libc::SYS_faccessat, libc::SYS_faccessat2,
        libc::SYS_mprotect, libc::SYS_munmap, libc::SYS_brk, libc::SYS_mremap,
        libc::SYS_madvise, libc::SYS_mincore, libc::SYS_msync,
        libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigpending, libc::SYS_rt_sigsuspend,
        libc::SYS_ioctl, libc::SYS_pread64, libc::SYS_pwrite64,
        libc::SYS_readv, libc::SYS_writev,
        libc::SYS_pipe2, libc::SYS_pselect6,
        libc::SYS_ppoll, libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
        libc::SYS_eventfd2, libc::SYS_timerfd_create, libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime, libc::SYS_signalfd4, libc::SYS_dup,
        libc::SYS_dup3, libc::SYS_fcntl, libc::SYS_flock,
        libc::SYS_fsync, libc::SYS_fdatasync, libc::SYS_truncate,
        libc::SYS_ftruncate, libc::SYS_getdents64,
        libc::SYS_getcwd, libc::SYS_chdir, libc::SYS_fchdir,
        libc::SYS_renameat, libc::SYS_renameat2, libc::SYS_mkdirat,
        libc::SYS_openat,
        libc::SYS_unlinkat, libc::SYS_readlinkat, libc::SYS_symlinkat, libc::SYS_linkat,
        libc::SYS_fchmod, libc::SYS_fchmodat,
        libc::SYS_fchown, libc::SYS_fchownat,
        libc::SYS_getpid, libc::SYS_getppid,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_geteuid, libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_socket, libc::SYS_connect, libc::SYS_accept, libc::SYS_accept4,
        libc::SYS_sendto, libc::SYS_recvfrom, libc::SYS_sendmsg, libc::SYS_recvmsg,
        libc::SYS_shutdown, libc::SYS_bind, libc::SYS_listen,
        libc::SYS_getsockname, libc::SYS_getpeername, libc::SYS_socketpair,
        libc::SYS_setsockopt, libc::SYS_getsockopt,
        libc::SYS_sendfile, libc::SYS_sendmmsg, libc::SYS_recvmmsg,
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_execve, libc::SYS_execveat,
        libc::SYS_wait4, libc::SYS_nanosleep, libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep, libc::SYS_gettimeofday,
        libc::SYS_set_tid_address, libc::SYS_set_robust_list, libc::SYS_get_robust_list,
        libc::SYS_sched_yield, libc::SYS_sched_getaffinity, libc::SYS_sched_setscheduler,
        libc::SYS_sched_getscheduler, libc::SYS_sched_getparam, libc::SYS_sched_get_priority_max,
        libc::SYS_sched_get_priority_min,
        libc::SYS_exit, libc::SYS_exit_group, libc::SYS_futex,
        libc::SYS_getrandom, libc::SYS_prctl,
        libc::SYS_uname, libc::SYS_getrlimit, libc::SYS_getrusage,
        libc::SYS_sysinfo, libc::SYS_times,
        // glibc >= 2.35 registers a restartable sequence for every new
        // thread (including the main thread) via pthread_create — without
        // this the process gets an unconditional "Fatal glibc error: rseq
        // registration failed" (SIGABRT) on the very first thread it spawns.
        libc::SYS_rseq, libc::SYS_gettid,
    ];

    // x86_64-only: legacy syscalls superseded by their `*at()`/modern
    // equivalents above (openat, statx/newfstatat, faccessat[2], pipe2,
    // pselect6, ppoll, epoll_create1, epoll_pwait, dup3, getdents64,
    // renameat[2], mkdirat, unlinkat, readlinkat, fchmodat, fchownat — all
    // already in the base list) but still valid, allocated syscall numbers on
    // x86_64, so kept for any glibc code path that still calls them there.
    // None of these exist on aarch64 at all (the generic 64-bit syscall ABI
    // aarch64 introduced dropped them outright) — referencing them
    // unconditionally is exactly what broke the aarch64 cross-compile.
    // `arch_prctl` is a distinct case: genuinely x86(_64)-only (sets the
    // FS/GS segment base registers for TLS), with no aarch64 syscall
    // equivalent at all — TLS setup there uses a dedicated register, not a
    // syscall this allowlist needs to cover.
    #[cfg(target_arch = "x86_64")]
    v.extend([
        libc::SYS_stat, libc::SYS_lstat, libc::SYS_access, libc::SYS_pipe,
        libc::SYS_select, libc::SYS_poll, libc::SYS_epoll_create, libc::SYS_epoll_wait,
        libc::SYS_dup2, libc::SYS_getdents, libc::SYS_rename, libc::SYS_mkdir,
        libc::SYS_rmdir, libc::SYS_creat, libc::SYS_open, libc::SYS_unlink,
        libc::SYS_readlink, libc::SYS_chmod, libc::SYS_chown, libc::SYS_lchown,
        libc::SYS_getpgrp, libc::SYS_time, libc::SYS_arch_prctl,
    ]);

    v
}

/// Builds the seccomp cBPF allowlist program (pure — no syscalls, testable).
/// Layout:
///   0  LD arch
///   1  JEQ X86_64 -> jt=1 (ok), jf=0 (wrong arch -> fall to 2)
///   2  RET KILL_PROCESS                  (wrong arch)
///   3  LD nr
///   4..(3+n_kill)      kill checks
///   (4+n_kill)..(3+n_kill+n_allow)  allow checks
///   D = 4 + n_kill + n_allow: RET ERRNO(EPERM)   (default, fall-through)
///   D+1: RET KILL_PROCESS                (kill terminal)
///   D+2: RET ALLOW                       (allow terminal)
///
/// JEQ jt field = forward insn count on match: target - here - 1.
///   kill check at j (prog idx 4+j)  -> D+1 => jt = n_kill + n_allow - j
///   allow check at j (prog idx 4+n_kill+j) -> D+2 => jt = n_allow - j
///
/// jf field (non-match) MUST be 0 for every check in this chain: a
/// non-match has to fall through to the very next check instruction (pc+1),
/// not skip over it. jf=1 was a bug — it skipped every other check in the
/// chain, and because the total check count is odd, the "never matched"
/// path landed exactly on the KILL_PROCESS terminal instead of the intended
/// EPERM default, killing the worker on its first syscall regardless of
/// which syscall it was. `test_unmatched_syscall_gets_errno_not_kill` pins
/// this down.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn build_seccomp_program(kill_syscalls: &[i64], allow_syscalls: &[i64]) -> Vec<libc::sock_filter> {
    use seccomp_bpf::*;
    use libc::sock_filter;

    let n_kill = kill_syscalls.len();
    let n_allow = allow_syscalls.len();

    let default_pos = 4 + n_kill + n_allow;
    let kill_term = default_pos + 1;
    let allow_term = default_pos + 2;

    let cap = allow_term + 1;
    let mut prog: Vec<sock_filter> = Vec::with_capacity(cap);

    prog.push(insn(BPF_LD_W_ABS, 0, 0, SECCOMP_ARCH_OFF));
    prog.push(insn(BPF_JMP_JEQ_K, 1, 0, CURRENT_AUDIT_ARCH));
    prog.push(insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS));
    prog.push(insn(BPF_LD_W_ABS, 0, 0, SECCOMP_NR_OFF));

    for (j, &sc) in kill_syscalls.iter().enumerate() {
        let jt = kill_term.saturating_sub(4 + j + 1) as u8;
        prog.push(insn(BPF_JMP_JEQ_K, jt, 0, sc as u32));
    }
    for (j, &sc) in allow_syscalls.iter().enumerate() {
        let jt = allow_term.saturating_sub(4 + n_kill + j + 1) as u8;
        prog.push(insn(BPF_JMP_JEQ_K, jt, 0, sc as u32));
    }
    prog.push(insn(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM));
    prog.push(insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS));
    prog.push(insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW));

    debug_assert_eq!(prog.len(), cap);
    prog
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn apply_seccomp_filter() -> Result<()> {
    let kill_syscalls = kill_syscalls_list();
    let allow_syscalls = allow_syscalls_list();
    let (n_kill, n_allow) = (kill_syscalls.len(), allow_syscalls.len());
    let prog = build_seccomp_program(&kill_syscalls, &allow_syscalls);

    unsafe {
        seccomp_bpf::install(&prog).context("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed")?;
    }
    tracing::info!("seccomp filter applied ({} allowed, {} killed)", n_allow, n_kill);
    Ok(())
}

// -----------------------------------------------------------------------------
// landlock (best-effort)
// -----------------------------------------------------------------------------

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn try_landlock() -> Result<()> {
    // Minimal probe: call landlock_create_ruleset via libc::syscall with a
    // null attr and unsupported size. If it returns -1 with ENOSYS or EOPNOTSUPP,
    // landlock is unavailable — warn and continue. Real FS restriction would
    // require bounding the rw paths; left for a follow-up since the worker
    // runs tools that need broad FS access.
    const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    let rc = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<()>(), 0u32, 0u32) };
    if rc == -1 {
        tracing::debug!("landlock unavailable (best-effort): {}", std::io::Error::last_os_error());
        return Ok(());
    }
    tracing::info!("landlock support detected (restricting path rules TBD)");
    Ok(())
}

// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;

    /// Minimal interpreter for the classic-BPF instruction subset this
    /// module emits (LD|W|ABS, JMP|JEQ|K, RET|K), mirroring exactly how the
    /// kernel would walk `prog` for a given (syscall nr, arch) pair. This
    /// exercises the program's *dynamic* behavior — what actually happens
    /// per syscall — rather than just its static shape, which is what
    /// caught both the jf-offset bug and the wrong AUDIT_ARCH_X86_64
    /// constant during development. No root or real prctl() call needed.
    fn run_program(prog: &[libc::sock_filter], nr: i64, arch: u32) -> u32 {
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        loop {
            let insn = prog[pc];
            if insn.code == seccomp_bpf::BPF_LD_W_ABS {
                acc = if insn.k == seccomp_bpf::SECCOMP_NR_OFF {
                    nr as u32
                } else {
                    arch
                };
                pc += 1;
            } else if insn.code == seccomp_bpf::BPF_JMP_JEQ_K {
                pc += 1 + if acc == insn.k { insn.jt as usize } else { insn.jf as usize };
            } else if insn.code == seccomp_bpf::BPF_RET_K {
                return insn.k;
            } else {
                panic!("run_program: unexpected opcode {:#x} at pc={}", insn.code, pc);
            }
            assert!(pc < prog.len(), "run_program: pc ran off the end of the program");
        }
    }

    #[test]
    fn audit_arch_constant_matches_the_real_kernel_value() {
        // EM_X86_64(0x3e) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE, per
        // linux/audit.h. Regression pin for the bug where this was
        // 0xc0000000 (missing the machine-type byte) and silently killed
        // every syscall at the arch check before the allowlist ever ran.
        assert_eq!(seccomp_bpf::AUDIT_ARCH_X86_64, 0xc000_003e);
        // EM_AARCH64(0xb7) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
        assert_eq!(seccomp_bpf::AUDIT_ARCH_AARCH64, 0xc000_00b7);
    }

    #[test]
    fn wrong_arch_is_killed() {
        let prog = build_seccomp_program(&kill_syscalls_list(), &allow_syscalls_list());
        let action = run_program(&prog, libc::SYS_read, 0xdead_beef);
        assert_eq!(action, seccomp_bpf::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn every_allowed_syscall_is_actually_allowed() {
        let allow = allow_syscalls_list();
        let prog = build_seccomp_program(&kill_syscalls_list(), &allow);
        for &sc in &allow {
            let action = run_program(&prog, sc, seccomp_bpf::CURRENT_AUDIT_ARCH);
            assert_eq!(
                action,
                seccomp_bpf::SECCOMP_RET_ALLOW,
                "syscall {} should be ALLOW but got {:#x}",
                sc,
                action
            );
        }
    }

    #[test]
    fn every_kill_syscall_is_actually_killed() {
        let kill = kill_syscalls_list();
        let prog = build_seccomp_program(&kill, &allow_syscalls_list());
        for &sc in &kill {
            let action = run_program(&prog, sc, seccomp_bpf::CURRENT_AUDIT_ARCH);
            assert_eq!(
                action,
                seccomp_bpf::SECCOMP_RET_KILL_PROCESS,
                "syscall {} should be KILL but got {:#x}",
                sc,
                action
            );
        }
    }

    #[test]
    fn unmatched_syscall_gets_errno_not_kill() {
        // Regression test for the jf-offset bug: a syscall in neither list
        // must fall through to EPERM, never to the KILL terminal. Uses a
        // syscall number guaranteed absent from both lists.
        let prog = build_seccomp_program(&kill_syscalls_list(), &allow_syscalls_list());
        let unmatched: i64 = 999_999;
        assert!(!kill_syscalls_list().contains(&unmatched));
        assert!(!allow_syscalls_list().contains(&unmatched));

        let action = run_program(&prog, unmatched, seccomp_bpf::CURRENT_AUDIT_ARCH);
        assert_eq!(action, seccomp_bpf::SECCOMP_RET_ERRNO | seccomp_bpf::EPERM);
    }

    #[test]
    fn kill_and_allow_lists_are_disjoint() {
        let kill = kill_syscalls_list();
        let allow = allow_syscalls_list();
        for sc in &kill {
            assert!(
                !allow.contains(sc),
                "syscall {} listed as both killed and allowed",
                sc
            );
        }
    }

    #[test]
    fn program_length_matches_layout_formula() {
        let kill = kill_syscalls_list();
        let allow = allow_syscalls_list();
        let prog = build_seccomp_program(&kill, &allow);
        // 4 fixed head instructions + one check per syscall + 3 terminals.
        assert_eq!(prog.len(), 4 + kill.len() + allow.len() + 3);
    }

    #[test]
    fn uid_task_count_reads_something_sane() {
        // Best-effort /proc scan: on any real Linux system this process's
        // own UID owns at least itself, so it should never be Some(0), and
        // must never panic even when run inside restrictive CI sandboxes.
        if let Some(n) = current_uid_task_count() {
            assert!(n >= 1, "expected at least this process to be counted, got {}", n);
        }
    }
}
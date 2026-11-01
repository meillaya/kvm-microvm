//! Feature-gated real-KVM runner for the educational direct-KVM subset.
//!
//! This module is compiled only with the `direct-kvm` feature. It is the
//! sole place in the crate that performs KVM ioctls:
//!
//! 1. Probe `/dev/kvm` (API version 12 + `KVM_CAP_USER_MEMORY`).
//! 2. `KVM_CREATE_VM` and register one identity-mapped 16 MiB memory slot at
//!    GPA 0 (`KVM_SET_USER_MEMORY_REGION`).
//! 3. `KVM_CREATE_VCPU(0)`, program 64-bit long mode (`KVM_SET_CPUID2`,
//!    `KVM_SET_SREGS`, `KVM_SET_REGS`).
//! 4. `KVM_RUN` loop feeding the pure [`ExitDispatcher`].
//! 5. Clean shutdown: deregister the slot, drop the vCPU/VM fds, `munmap`.
//!
//! Thread contract (requirement 8): the vCPU is created and run on the
//! thread that constructed the [`VmRunner`]; `run()` asserts this. KVM vCPU fds
//! must not migrate between threads, and the educational subset never spawns.
//!
//! No fallback (requirement 5): a missing/incompatible `/dev/kvm` yields
//! [`RunOutcome::Blocked`]; this module never references Firecracker/QEMU/TCG
//! and never converts a blocked or failed boot into a pass.

use crate::dispatch::{DispatchAction, ExitDispatcher, GuestExit};
use crate::guest;
use crate::outcome::{BlockedReason, FailureReason, RunOutcome, StopReason};
use crate::probe::{self, ProbeReport};
use crate::serial::SerialOutput;
use crate::{MEMORY_GUEST_PHYS_ADDR, MEMORY_SIZE_BYTES, MEMORY_SLOT};

use kvm_bindings::{
    kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, ThreadId};

/// Bound on `KVM_RUN` iterations so the loop always terminates even if a guest
/// never halts. Far above the marker guest's two exits.
pub const MAX_RUN_ITERATIONS: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Guest memory (mmap-backed, identity-mapped into the single slot)
// ---------------------------------------------------------------------------

/// A 16 MiB anonymous private mapping used as the single guest memory slot.
///
/// Matches the design doc: `mmap(MAP_ANONYMOUS | MAP_PRIVATE)`. The mapping is
/// released on drop. Used only on the creating thread (not `Send`/`Sync`).
struct GuestMemory {
    addr: *mut u8,
    size: usize,
}

impl GuestMemory {
    fn new(size: usize) -> Result<Self, String> {
        // SAFETY: mmap of an anonymous private region with no file descriptor;
        // the returned pointer is checked against MAP_FAILED before use.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(format!(
                "mmap({size} bytes) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            addr: ptr.cast::<u8>(),
            size,
        })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the mapping is valid for `size` bytes until munmap (in Drop),
        // and is only aliased through this single owner on the creating thread.
        unsafe { std::slice::from_raw_parts_mut(self.addr, self.size) }
    }

    fn addr_u64(&self) -> u64 {
        self.addr as u64
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        // SAFETY: addr/size came from a successful mmap and are unmapped once.
        unsafe {
            libc::munmap(self.addr.cast::<libc::c_void>(), self.size);
        }
    }
}

// ---------------------------------------------------------------------------
// VmRunner
// ---------------------------------------------------------------------------

/// Owns the KVM system fd, the VM fd, and the single guest memory slot, and
/// drives one vCPU through the marker guest.
///
/// Construct with [`VmRunner::new`] (or [`run_subset_boot_at`]) and call
/// [`VmRunner::run`] on the same thread.
pub struct VmRunner {
    kvm: Kvm,
    vm: VmFd,
    mem: GuestMemory,
    probe: ProbeReport,
    creating_thread: ThreadId,
    stop: Arc<AtomicBool>,
}

impl VmRunner {
    /// Opens KVM at `device`, probes it, creates the VM, and registers the
    /// single 16 MiB identity-mapped memory slot with the marker guest laid out.
    ///
    /// # Errors
    ///
    /// Returns a terminal [`RunOutcome::Blocked`] when `/dev/kvm` is missing or
    /// incompatible, or [`RunOutcome::Failed`] when VM/memory-slot setup fails.
    pub fn new(device: &str) -> Result<Self, RunOutcome> {
        let (kvm, probe) =
            probe::open_and_probe(device).map_err(probe::ProbeError::into_blocked)?;

        let vm = kvm.create_vm().map_err(|e| RunOutcome::Failed {
            reason: FailureReason::KvmIoctl,
            detail: format!("KVM_CREATE_VM: errno {}", e.errno()),
            serial: SerialOutput::new(),
        })?;

        let mut mem =
            GuestMemory::new(MEMORY_SIZE_BYTES as usize).map_err(|detail| RunOutcome::Failed {
                reason: FailureReason::KvmIoctl,
                detail,
                serial: SerialOutput::new(),
            })?;
        guest::write_boot_layout(mem.as_mut_slice());

        let region = kvm_userspace_memory_region {
            slot: MEMORY_SLOT,
            flags: 0,
            guest_phys_addr: MEMORY_GUEST_PHYS_ADDR,
            memory_size: MEMORY_SIZE_BYTES,
            userspace_addr: mem.addr_u64(),
        };
        // SAFETY: `region.userspace_addr` points to a live mapping owned by
        // `mem` (kept alive in the returned runner) for `memory_size` bytes; the
        // guest only accesses GPAs inside this single identity-mapped slot.
        unsafe { vm.set_user_memory_region(region) }.map_err(|e| RunOutcome::Failed {
            reason: FailureReason::KvmIoctl,
            detail: format!("KVM_SET_USER_MEMORY_REGION: errno {}", e.errno()),
            serial: SerialOutput::new(),
        })?;

        Ok(Self {
            kvm,
            vm,
            mem,
            probe,
            creating_thread: thread::current().id(),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The successful probe report (API version + capabilities).
    #[must_use]
    pub fn probe(&self) -> &ProbeReport {
        &self.probe
    }

    /// A shared flag that, when set, stops the vCPU loop between `KVM_RUN`
    /// iterations (`StopBehavior::HostStop`). May be set from another thread;
    /// the vCPU itself still runs only on the creating thread.
    #[must_use]
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Runs the marker guest on one vCPU and returns the terminal outcome.
    ///
    /// # Panics
    ///
    /// Panics if called from a thread other than the one that constructed the
    /// runner (KVM vCPU operations must remain on the creating thread).
    pub fn run(&mut self) -> RunOutcome {
        assert_eq!(
            thread::current().id(),
            self.creating_thread,
            "vCPU operations must remain on the creating thread"
        );

        let mut vcpu = match self.vm.create_vcpu(0) {
            Ok(vcpu) => vcpu,
            Err(e) => {
                return ioctl_failure("KVM_CREATE_VCPU", e.errno(), SerialOutput::new());
            }
        };

        if let Err(detail) = set_supported_cpuid(&self.kvm, &vcpu) {
            return RunOutcome::Failed {
                reason: FailureReason::KvmIoctl,
                detail,
                serial: SerialOutput::new(),
            };
        }

        if let Err(e) = setup_long_mode(&vcpu) {
            return ioctl_failure("KVM_SET_SREGS/KVM_SET_REGS", e.errno(), SerialOutput::new());
        }

        self.run_loop(&mut vcpu)
    }

    /// The bounded `KVM_RUN` loop feeding the pure exit dispatcher.
    fn run_loop(&self, vcpu: &mut VcpuFd) -> RunOutcome {
        let mut dispatcher = ExitDispatcher::new();
        let mut iterations = 0u32;

        loop {
            if self.stop.load(Ordering::SeqCst) {
                dispatcher.request_host_stop();
            }
            iterations += 1;
            if iterations > MAX_RUN_ITERATIONS {
                return RunOutcome::Failed {
                    reason: FailureReason::RunawayLoop,
                    detail: format!("exceeded {MAX_RUN_ITERATIONS} KVM_RUN iterations"),
                    serial: dispatcher.into_serial(),
                };
            }

            let exit = match vcpu.run() {
                Ok(exit) => exit,
                Err(e) => return self.on_run_error(e.errno(), dispatcher),
            };

            // Copy the owned exit data out first; `exit` borrows `vcpu` and is
            // unused afterwards, so its borrow ends before `finalize_exit`
            // reads the `kvm_run` shared page for the deferred fields.
            let class = exit_class(&exit);
            let guest_exit = finalize_exit(vcpu, class);
            match dispatcher.dispatch(guest_exit) {
                DispatchAction::Continue => {}
                DispatchAction::Stop(stop) => {
                    return RunOutcome::Completed {
                        serial: dispatcher.into_serial(),
                        stop,
                    };
                }
                DispatchAction::Fail(reason, detail) => {
                    return RunOutcome::Failed {
                        reason,
                        detail,
                        serial: dispatcher.into_serial(),
                    };
                }
            }
        }
    }

    fn on_run_error(&self, errno: i32, dispatcher: ExitDispatcher) -> RunOutcome {
        // EINTR means a signal (e.g. the host-stop path) interrupted KVM_RUN.
        if errno == libc::EINTR {
            return RunOutcome::Completed {
                serial: dispatcher.into_serial(),
                stop: StopReason::HostStop,
            };
        }
        ioctl_failure("KVM_RUN", errno, dispatcher.into_serial())
    }
}

impl Drop for VmRunner {
    fn drop(&mut self) {
        // Clean shutdown: deregister the single memory slot before the mapping
        // is released. Setting memory_size = 0 deletes the slot. The vCPU fd is
        // already dropped when run() returned; the VM fd drops here.
        let region = kvm_userspace_memory_region {
            slot: MEMORY_SLOT,
            flags: 0,
            guest_phys_addr: MEMORY_GUEST_PHYS_ADDR,
            memory_size: 0,
            userspace_addr: 0,
        };
        // SAFETY: deleting a slot we previously registered; no guest is running
        // by the time the runner is dropped.
        let _ = unsafe { self.vm.set_user_memory_region(region) };
        // `self.mem` drops afterwards (field order), munmap-ing the region only
        // after the slot is deregistered.
        let _ = &self.mem;
    }
}

// ---------------------------------------------------------------------------
// vCPU setup helpers
// ---------------------------------------------------------------------------

/// Installs the host-supported CPUID into the vCPU (`KVM_SET_CPUID2`).
fn set_supported_cpuid(kvm: &Kvm, vcpu: &VcpuFd) -> Result<(), String> {
    let cpuid = kvm
        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .map_err(|e| format!("KVM_GET_SUPPORTED_CPUID: errno {}", e.errno()))?;
    vcpu.set_cpuid2(&cpuid)
        .map_err(|e| format!("KVM_SET_CPUID2: errno {}", e.errno()))
}

/// Programs 64-bit long mode: control registers + `EFER`, a 64-bit code
/// segment, the GDT, and the initial registers (RIP=0, RFLAGS=0x2).
fn setup_long_mode(vcpu: &VcpuFd) -> Result<(), kvm_ioctls::Error> {
    let mut sregs: kvm_sregs = vcpu.get_sregs()?;

    sregs.cr0 = guest::INITIAL_CR0;
    sregs.cr3 = guest::INITIAL_CR3;
    sregs.cr4 = guest::INITIAL_CR4;
    sregs.efer = guest::INITIAL_EFER;

    sregs.gdt.base = guest::GDT_GPA;
    sregs.gdt.limit = guest::GDT_SIZE_BYTES as u16 - 1;

    sregs.cs = code_segment();
    let data = data_segment();
    sregs.ds = data;
    sregs.es = data;
    sregs.ss = data;

    vcpu.set_sregs(&sregs)?;

    let regs = kvm_regs {
        rip: guest::INITIAL_RIP,
        rsp: guest::INITIAL_RSP,
        rflags: guest::INITIAL_RFLAGS,
        ..Default::default()
    };
    vcpu.set_regs(&regs)
}

/// The 64-bit code segment (selector `0x08`, L=1, D/B=0).
fn code_segment() -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: guest::GDT_CODE_SELECTOR,
        type_: guest::SEG_TYPE_CODE,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1,
        g: 0,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

/// The data segment (selector `0x10`).
fn data_segment() -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: guest::GDT_DATA_SELECTOR,
        type_: guest::SEG_TYPE_DATA,
        present: 1,
        dpl: 0,
        db: 1,
        s: 1,
        l: 0,
        g: 0,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

// ---------------------------------------------------------------------------
// Exit classification
// ---------------------------------------------------------------------------

/// Owned pre-classification of a `VcpuExit`.
///
/// Every field is copied out of the borrowed `VcpuExit`, so producing this
/// value releases the borrow on the vCPU and lets the runner read the
/// `kvm_run` shared page afterwards.
enum ExitClass {
    IoOut { port: u16, byte: u8 },
    Hlt,
    FailEntry { reason: u64 },
    InternalError,
    Unexpected,
}

/// Copies the owned data out of a real `VcpuExit` (no borrow retained).
fn exit_class(exit: &VcpuExit<'_>) -> ExitClass {
    match exit {
        VcpuExit::IoOut(port, data) => ExitClass::IoOut {
            port: *port,
            byte: data.first().copied().unwrap_or(0),
        },
        VcpuExit::Hlt => ExitClass::Hlt,
        VcpuExit::FailEntry(reason, _cpu) => ExitClass::FailEntry { reason: *reason },
        VcpuExit::InternalError => ExitClass::InternalError,
        _ => ExitClass::Unexpected,
    }
}

/// Finalizes the classification into the backend-neutral [`GuestExit`], reading
/// the `kvm_run` shared page for the fields the high-level enum does not carry
/// (`InternalError` suberror, unexpected raw reason). Must be called only after
/// the `VcpuExit` borrow has been dropped.
fn finalize_exit(vcpu: &mut VcpuFd, class: ExitClass) -> GuestExit {
    match class {
        ExitClass::IoOut { port, byte } => GuestExit::IoOut { port, byte },
        ExitClass::Hlt => GuestExit::Hlt,
        ExitClass::FailEntry { reason } => GuestExit::FailEntry {
            hardware_entry_failure_reason: reason,
        },
        ExitClass::InternalError => GuestExit::InternalError {
            suberror: internal_suberror(vcpu),
        },
        ExitClass::Unexpected => GuestExit::Unexpected {
            reason_code: exit_reason_code(vcpu),
        },
    }
}

/// Reads `internal.suberror` from the `kvm_run` shared page.
fn internal_suberror(vcpu: &mut VcpuFd) -> u32 {
    // SAFETY: `internal` is the active union member when the exit reason is
    // KVM_EXIT_INTERNAL_ERROR, which is the only path that calls this.
    unsafe { vcpu.get_kvm_run().__bindgen_anon_1.internal.suberror }
}

/// Reads the raw exit reason number from the `kvm_run` shared page.
fn exit_reason_code(vcpu: &mut VcpuFd) -> u32 {
    vcpu.get_kvm_run().exit_reason
}

// ---------------------------------------------------------------------------
// Outcome helpers
// ---------------------------------------------------------------------------

fn ioctl_failure(op: &str, errno: i32, serial: SerialOutput) -> RunOutcome {
    RunOutcome::Failed {
        reason: FailureReason::KvmIoctl,
        detail: format!("{op}: errno {errno}"),
        serial,
    }
}

/// Runs the marker guest on real KVM at the default device (`/dev/kvm`).
///
/// Never panics on a missing device: returns [`RunOutcome::Blocked`] when KVM
/// is unavailable, [`RunOutcome::Completed`] when the marker was observed.
#[must_use]
pub fn run_subset_boot() -> RunOutcome {
    run_subset_boot_at(probe::DEFAULT_KVM_DEVICE)
}

/// Runs the marker guest on real KVM at `device`.
///
/// This is the single entry point used by the privileged test and any host
/// tooling. It opens the device exactly once and maps every error to a
/// structured outcome (blocked or failed); never a fallback, never a panic.
#[must_use]
pub fn run_subset_boot_at(device: &str) -> RunOutcome {
    match VmRunner::new(device) {
        Ok(mut runner) => runner.run(),
        Err(outcome) => outcome,
    }
}

/// Convenience: the blocked reason for a missing device path, used to assert
/// the "missing `/dev/kvm` ⇒ blocked, not pass" contract from callers.
#[must_use]
pub fn blocked_reason_for_device(device: &str) -> Option<BlockedReason> {
    match probe::open_and_probe(device) {
        Ok(_) => None,
        Err(e) => Some(e.blocked_reason()),
    }
}

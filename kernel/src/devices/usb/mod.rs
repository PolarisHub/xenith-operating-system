//! USB input foundation: PCI xHCI plus HID keyboard/mouse boot protocol.
//!
//! Runtime coverage is deliberately explicit:
//!
//! * xHCI PCI class matching, BAR0 validation, BIOS/OS ownership handoff,
//!   controller reset/start, DCBAA/scratchpad/command/event-ring setup;
//! * direct root-port reset and device addressing (no external hubs);
//! * standard EP0 GET_DESCRIPTOR/SET_CONFIGURATION control transfers;
//! * HID subclass-1 boot keyboard and mouse interface discovery;
//! * Configure Endpoint, SET_PROTOCOL(boot), SET_IDLE, interrupt-IN Normal
//!   TRB requeue, and delivery through Xenith's existing ordered UI input
//!   path;
//! * single-message MSI when available, with a public polling/service fallback.
//!
//! It does **not** claim EHCI/OHCI/UHCI, USB hubs, mass storage, audio, generic
//! HID report descriptors, isochronous transfers, or arbitrary vendor classes.
//!
//! # Specification anchors
//!
//! Register/context/TRB constants follow the *xHCI Specification 1.2* sections
//! 4.2-4.6 (initialization, device slots, endpoints), 5.3-5.5 (registers),
//! 6.2 (contexts), and 6.4 (TRBs/rings). Descriptor requests and layouts follow
//! *USB 2.0* chapter 9. Boot reports and class requests follow *HID 1.11*
//! sections 7.2 and appendix B. The code cites the relevant structure again at
//! each ownership-sensitive boundary.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::devices::pci::capability::{
    self, MsiCapability, MsixCapability, CAP_ID_MSI, CAP_ID_MSIX,
};
use crate::devices::pci::enumerate::{self, PciDevice, PciDriver, PciDriverError};
use crate::devices::pci::PciCommand;
use crate::sync::SpinLock;

pub mod descriptor;
pub mod hid;
pub mod xhci;

/// Dedicated vector for xHCI single-message MSI.
pub const XHCI_VECTOR: u8 = 0x41;
const MAX_CONTROLLERS: usize = 2;
const SERVICE_INTERVAL_MS: u64 = 4;

core::arch::global_asm!(
    r#"
    .section .text
    .global xenith_xhci_irq
xenith_xhci_irq:
    test byte ptr [rsp + 8], 1
    jz 1f
    test byte ptr [rsp + 8], 2
    jz 1f
    swapgs
1:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsp
    and rsp, -16
    call xenith_xhci_irq_rust
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    test byte ptr [rsp + 8], 1
    jz 2f
    test byte ptr [rsp + 8], 2
    jz 2f
    swapgs
2:
    iretq
"#,
);

extern "C" {
    fn xenith_xhci_irq();
}

struct ControllerRegistry {
    controllers: [Option<xhci::XhciController>; MAX_CONTROLLERS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryAdmissionError {
    Duplicate,
    Full,
}

fn registry_admission(
    existing: &[Option<crate::devices::pci::PciAddress>; MAX_CONTROLLERS],
    candidate: crate::devices::pci::PciAddress,
) -> Result<usize, RegistryAdmissionError> {
    if existing.contains(&Some(candidate)) {
        return Err(RegistryAdmissionError::Duplicate);
    }
    existing
        .iter()
        .position(Option::is_none)
        .ok_or(RegistryAdmissionError::Full)
}

impl ControllerRegistry {
    const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
        }
    }

    fn admission_index(
        &self,
        candidate: crate::devices::pci::PciAddress,
    ) -> Result<usize, RegistryAdmissionError> {
        let existing = core::array::from_fn(|index| {
            self.controllers[index]
                .as_ref()
                .map(xhci::XhciController::pci_address)
        });
        registry_admission(&existing, candidate)
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut xhci::XhciController> {
        self.controllers.iter_mut().flatten()
    }
}

static CONTROLLERS: SpinLock<ControllerRegistry> = SpinLock::new(ControllerRegistry::new());
static SERVICE_WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static INTERRUPTS: AtomicU64 = AtomicU64::new(0);
static EVENTS: AtomicU64 = AtomicU64::new(0);

struct XhciPciDriver;
static XHCI_DRIVER: XhciPciDriver = XhciPciDriver;

impl PciDriver for XhciPciDriver {
    fn name(&self) -> &'static str {
        "xhci-hid"
    }

    fn matches(&self, device: &PciDevice) -> bool {
        xhci::is_xhci(device)
    }

    fn probe(&self, device: &PciDevice) -> Result<(), PciDriverError> {
        // Admission is checked while holding the registry lock and before any
        // MMIO/configuration write. In particular, a third or duplicate xHC
        // cannot be started and then dropped with live DMA pointers.
        let mut registry = CONTROLLERS.lock();
        let index = registry
            .admission_index(device.address)
            .map_err(|error| match error {
                RegistryAdmissionError::Duplicate => {
                    PciDriverError::ProbeFailed("duplicate xHCI controller")
                },
                RegistryAdmissionError::Full => {
                    PciDriverError::ProbeFailed("xHCI controller registry full")
                },
            })?;
        disable_message_interrupts(device).map_err(|_| {
            PciDriverError::ProbeFailed("malformed xHCI PCI interrupt capabilities")
        })?;
        let controller = xhci::XhciController::new(device)
            .map_err(|_| PciDriverError::ProbeFailed("xHCI initialization or HID enumeration"))?;
        // `index` names a vacant slot observed under this same still-held
        // lock, so insertion has no fallible post-start path.
        registry.controllers[index] = Some(controller);
        drop(registry);
        match configure_msi(device) {
            Ok(true) => ::log::info!("usb: xHCI controller {} using MSI", index),
            Ok(false) => ::log::warn!(
                "usb: xHCI controller {} has no usable MSI; call usb::service() periodically",
                index
            ),
            Err(error) => ::log::warn!(
                "usb: xHCI controller {} malformed PCI capabilities {:?}; polling mode",
                index,
                error
            ),
        }
        Ok(())
    }
}

fn disable_message_interrupts(device: &PciDevice) -> Result<(), capability::CapabilityError> {
    let capabilities = capability::walk(device.address)?;
    if let Some(msix) = capabilities.find(CAP_ID_MSIX) {
        MsixCapability::read(device.address, msix)?.disable(device.address);
    }
    if let Some(msi) = capabilities.find(CAP_ID_MSI) {
        MsiCapability::read(device.address, msi)?.disable(device.address);
    }
    Ok(())
}

/// Install the xHCI IDT gate and register the class driver before PCI binding.
pub fn register_pci_driver() {
    {
        let mut idt = crate::arch::x86_64::idt::IDT.lock();
        idt.set_interrupt_handler(u16::from(XHCI_VECTOR), xenith_xhci_irq);
    }
    enumerate::register_driver(&XHCI_DRIVER);
}

/// Spawn the bounded task-context service loop exactly once.
///
/// Call after the scheduler is initialized. The worker supplies real report
/// polling when MSI is unavailable and performs connect/disconnect enumeration
/// that the hard IRQ deliberately defers because it may allocate DMA memory
/// and wait for commands. A 4 ms cadence is faster than the common 8 ms USB
/// boot-mouse interval without busy-spinning.
pub fn start_service_worker() {
    if SERVICE_WORKER_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = crate::sched::kthread::spawn_kernel_thread("usb-service", service_worker, 0);
    ::log::info!(
        "usb: task-context service worker online ({} ms)",
        SERVICE_INTERVAL_MS
    );
}

extern "C" fn service_worker(_argument: usize) -> usize {
    loop {
        let _ = service();
        crate::sched::sleep_until(
            crate::time::Instant::now() + crate::time::Duration::from_millis(SERVICE_INTERVAL_MS),
        );
    }
}

fn configure_msi(device: &PciDevice) -> Result<bool, capability::CapabilityError> {
    let address = device.address;
    let capabilities = capability::walk(address)?;
    if let Some(msix) = capabilities.find(CAP_ID_MSIX) {
        MsixCapability::read(address, msix)?.disable(address);
    }
    let Some(msi_entry) = capabilities.find(CAP_ID_MSI) else {
        return Ok(false);
    };
    let msi = MsiCapability::read(address, msi_entry)?;
    msi.disable(address);
    let Ok(destination) = u8::try_from(crate::arch::x86_64::interrupts::apic::current_id()) else {
        return Ok(false);
    };
    let mut command = PciCommand::from_bits_truncate(address.read_command());
    command.insert(PciCommand::INTERRUPT_DISABLE);
    address.write_command(command.bits());
    msi.program_single(address, destination, XHCI_VECTOR)?;
    Ok(true)
}

/// Drain completed reports and process deferred root-port hotplug work.
///
/// This is the authoritative fallback for controllers without MSI and the
/// task-context half of hotplug handling for MSI controllers. It performs
/// bounded work per controller and never holds the registry across unrelated
/// subsystem calls.
pub fn service() -> usize {
    let mut total = 0usize;
    let mut controllers = CONTROLLERS.lock();
    for controller in controllers.iter_mut() {
        total = total.saturating_add(controller.service());
    }
    total
}

/// Number of initialized xHCI controllers.
#[must_use]
pub fn controller_count() -> usize {
    CONTROLLERS.lock().controllers.iter().flatten().count()
}

/// Number of active keyboard/mouse boot interfaces (a composite device can
/// contribute two).
#[must_use]
pub fn hid_interface_count() -> usize {
    CONTROLLERS
        .lock()
        .controllers
        .iter()
        .flatten()
        .map(xhci::XhciController::hid_device_count)
        .sum()
}

/// xHCI interrupt and drained-event counters for diagnostics.
#[must_use]
pub fn irq_stats() -> (u64, u64) {
    (
        INTERRUPTS.load(Ordering::Relaxed),
        EVENTS.load(Ordering::Relaxed),
    )
}

#[no_mangle]
extern "C" fn xenith_xhci_irq_rust() {
    INTERRUPTS.fetch_add(1, Ordering::Relaxed);
    let mut handled = 0usize;
    // A task-context service call may own the registry. Never spin behind it
    // from a hard IRQ; the event remains in the xHC ring and the service path
    // will acknowledge it before re-enabling progress.
    if let Some(mut controllers) = CONTROLLERS.try_lock() {
        for controller in controllers.iter_mut() {
            handled = handled.saturating_add(controller.handle_interrupt());
        }
    }
    EVENTS.fetch_add(handled as u64, Ordering::Relaxed);
    crate::arch::x86_64::interrupts::apic::send_eoi();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::pci::enumerate::PciHeaderKind;
    use crate::devices::pci::PciAddress;

    #[test]
    fn pci_driver_matches_only_xhci_class_triple() {
        let mut device = PciDevice {
            address: PciAddress::new(0, 20, 0).unwrap(),
            vendor_id: 0x8086,
            device_id: 0x1e31,
            revision: 4,
            prog_if: 0x30,
            subclass: 0x03,
            base_class: 0x0c,
            header_kind: PciHeaderKind::Device,
            multifunction: false,
            bars: [0xfebf_0004, 0, 0, 0, 0, 0],
            interrupt_line: 11,
            interrupt_pin: 1,
        };
        assert!(XHCI_DRIVER.matches(&device));
        device.prog_if = 0x20;
        assert!(!XHCI_DRIVER.matches(&device));
    }

    #[test]
    fn registry_admission_rejects_duplicate_and_third_controller_preflight() {
        let first = PciAddress::new(0, 20, 0).unwrap();
        let second = PciAddress::new(0, 21, 0).unwrap();
        let third = PciAddress::new(0, 22, 0).unwrap();

        assert_eq!(registry_admission(&[None, None], first), Ok(0));
        assert_eq!(registry_admission(&[Some(first), None], second), Ok(1));
        assert_eq!(
            registry_admission(&[Some(first), None], first),
            Err(RegistryAdmissionError::Duplicate)
        );
        assert_eq!(
            registry_admission(&[Some(first), Some(second)], third),
            Err(RegistryAdmissionError::Full)
        );
    }
}

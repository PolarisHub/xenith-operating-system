//! PCI Ethernet adapters with interrupt-assisted, polling-safe packet I/O.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub mod dma;
pub mod e1000;
pub mod rtl8139;

use crate::mm::KVec;
use crate::net::eth::MacAddress;
use crate::net::{IngressOutcome, OutboundFrame};
use crate::sync::SpinLock;

const MAX_FRAME_LEN: usize = 1514;
const MAX_IRQ_BINDINGS: usize = 16;
const MAX_PENDING_ADAPTERS: usize = u64::BITS as usize;
/// Shared IDT vector for all level-triggered PCI NIC INTx routes.
pub const NIC_VECTOR: u8 = 0x40;

// External interrupts need an IRETQ epilogue and a complete integer-register
// save. All routed NICs share one vector; the Rust side reads each bounded
// cause register and therefore supports PCI INTx sharing without guessing
// which function asserted the line.
core::arch::global_asm!(
    r#"
    .section .text
    .global xenith_net_irq
xenith_net_irq:
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
    call xenith_net_irq_rust
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
    fn xenith_net_irq();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverError {
    UnsupportedBar,
    DmaUnavailable,
    DmaAddressTooHigh,
    ResetTimeout,
    InvalidMac,
    DeviceFault,
    FrameTooLarge,
    BufferTooSmall,
    WouldBlock,
    NoPacket,
    InvalidAdapter,
}

impl From<dma::DmaError> for DriverError {
    fn from(error: dma::DmaError) -> Self {
        match error {
            dma::DmaError::AddressTooHigh => Self::DmaAddressTooHigh,
            _ => Self::DmaUnavailable,
        }
    }
}

pub trait NetworkAdapter {
    fn driver_name(&self) -> &'static str;
    fn mac_address(&self) -> MacAddress;
    fn link_up(&self) -> bool;
    fn mtu(&self) -> usize;
    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError>;
    fn poll_receive(&mut self, output: &mut [u8]) -> Result<usize, DriverError>;
}

pub enum Adapter {
    Rtl8139(rtl8139::Rtl8139),
    E1000(e1000::E1000),
}

#[derive(Clone, Copy)]
pub(in crate::devices::net) enum IrqDevice {
    Rtl8139(rtl8139::InterruptHandle),
    E1000(e1000::InterruptHandle),
}

impl IrqDevice {
    fn acknowledge_and_mask(self) -> u32 {
        match self {
            Self::Rtl8139(handle) => handle.acknowledge_and_mask(),
            Self::E1000(handle) => handle.acknowledge_and_mask(),
        }
    }

    fn enable(self) {
        match self {
            Self::Rtl8139(handle) => handle.enable(),
            Self::E1000(handle) => handle.enable(),
        }
    }
}

#[derive(Clone, Copy)]
struct IrqBinding {
    adapter_index: usize,
    device: IrqDevice,
}

struct IrqRegistry {
    entries: [Option<IrqBinding>; MAX_IRQ_BINDINGS],
    count: usize,
}

impl IrqRegistry {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_IRQ_BINDINGS],
            count: 0,
        }
    }

    fn can_push(&self, adapter_index: usize) -> bool {
        self.count != self.entries.len()
            && !self.entries[..self.count]
                .iter()
                .flatten()
                .any(|entry| entry.adapter_index == adapter_index)
    }

    fn push(&mut self, binding: IrqBinding) -> bool {
        if !self.can_push(binding.adapter_index) {
            return false;
        }
        self.entries[self.count] = Some(binding);
        self.count += 1;
        true
    }

    fn iter(&self) -> impl Iterator<Item = IrqBinding> + '_ {
        self.entries[..self.count].iter().flatten().copied()
    }

    fn find(&self, adapter_index: usize) -> Option<IrqBinding> {
        self.iter()
            .find(|binding| binding.adapter_index == adapter_index)
    }
}

/// Snapshot of the bounded hard-IRQ path for diagnostics and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrqStats {
    pub interrupts: u64,
    pub claimed_devices: u64,
    pub worker_wakes: u64,
    pub wake_contentions: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct AdapterInfo {
    pub index: usize,
    pub interface: u16,
    pub driver: &'static str,
    pub mac: MacAddress,
    pub link_up: bool,
    pub mtu: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PollReport {
    pub received: usize,
    pub delivered: usize,
    pub replies: usize,
    pub dropped: usize,
    pub driver_errors: usize,
    pub stack_errors: usize,
}

impl Adapter {
    fn bdf(&self) -> (u8, u8, u8) {
        match self {
            Self::Rtl8139(adapter) => adapter.bdf(),
            Self::E1000(adapter) => adapter.bdf(),
        }
    }
}

impl NetworkAdapter for Adapter {
    fn driver_name(&self) -> &'static str {
        match self {
            Self::Rtl8139(adapter) => adapter.driver_name(),
            Self::E1000(adapter) => adapter.driver_name(),
        }
    }

    fn mac_address(&self) -> MacAddress {
        match self {
            Self::Rtl8139(adapter) => adapter.mac_address(),
            Self::E1000(adapter) => adapter.mac_address(),
        }
    }

    fn link_up(&self) -> bool {
        match self {
            Self::Rtl8139(adapter) => adapter.link_up(),
            Self::E1000(adapter) => adapter.link_up(),
        }
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        match self {
            Self::Rtl8139(adapter) => adapter.transmit(frame),
            Self::E1000(adapter) => adapter.transmit(frame),
        }
    }

    fn poll_receive(&mut self, output: &mut [u8]) -> Result<usize, DriverError> {
        match self {
            Self::Rtl8139(adapter) => adapter.poll_receive(output),
            Self::E1000(adapter) => adapter.poll_receive(output),
        }
    }
}

static ADAPTERS: SpinLock<KVec<Adapter>> = SpinLock::new(KVec::new());
static IRQ_BINDINGS: SpinLock<IrqRegistry> = SpinLock::new(IrqRegistry::new());
static IRQ_HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);
static IRQ_PENDING: AtomicU64 = AtomicU64::new(0);
static NETWORK_WORKER_TASK: AtomicU64 = AtomicU64::new(0);
static IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
static IRQ_CLAIMED_DEVICES: AtomicU64 = AtomicU64::new(0);
static IRQ_WORKER_WAKES: AtomicU64 = AtomicU64::new(0);
static IRQ_WAKE_CONTENTIONS: AtomicU64 = AtomicU64::new(0);

pub(super) fn attach(adapter: Adapter) -> Option<usize> {
    let mut adapters = ADAPTERS.lock();
    if adapters
        .iter()
        .any(|existing| existing.bdf() == adapter.bdf())
    {
        return None;
    }
    let index = adapters.len();
    adapters.push(adapter);
    Some(index)
}

pub fn register_pci_drivers() {
    install_irq_handler();
    rtl8139::register_pci_driver();
    e1000::register_pci_driver();
}

fn install_irq_handler() {
    if IRQ_HANDLER_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut idt = crate::arch::x86_64::idt::IDT.lock();
    idt.set_interrupt_handler(u16::from(NIC_VECTOR), xenith_net_irq);
}

fn fallback_intx_gsi(interrupt_line: u8, interrupt_pin: u8) -> Option<u32> {
    if !(1..=4).contains(&interrupt_pin)
        || matches!(interrupt_line, 0 | 0xff)
        || matches!(
            interrupt_line,
            crate::devices::ps2::KEYBOARD_IRQ | crate::devices::ps2::MOUSE_IRQ
        )
    {
        return None;
    }
    Some(u32::from(interrupt_line))
}

fn valid_nic_gsi(gsi: u32) -> bool {
    !matches!(gsi, 1 | 12)
}

fn pending_bit(adapter_index: usize) -> Option<u64> {
    (adapter_index < MAX_PENDING_ADAPTERS).then(|| 1u64 << adapter_index)
}

/// Route a firmware-provided legacy INTx line and publish its device cause
/// handle before the controller is enabled. Failure deliberately leaves the
/// adapter's interrupt mask clear; the autonomous poller remains authoritative.
pub(in crate::devices::net) fn configure_intx(
    device: &crate::devices::pci::enumerate::PciDevice,
    adapter_index: usize,
    irq_device: IrqDevice,
) -> bool {
    let aml_gsi =
        crate::devices::pci::routing::resolve_intx(device).filter(|gsi| valid_nic_gsi(*gsi));
    let Some(gsi) =
        aml_gsi.or_else(|| fallback_intx_gsi(device.interrupt_line, device.interrupt_pin))
    else {
        return false;
    };
    if pending_bit(adapter_index).is_none() || crate::arch::x86_64::interrupts::ioapic::count() == 0
    {
        return false;
    }
    let apic_id = crate::arch::x86_64::interrupts::apic::current_id();
    let Ok(destination) = u8::try_from(apic_id) else {
        ::log::warn!(
            "net: APIC id {} cannot be represented by an IOAPIC INTx destination",
            apic_id
        );
        return false;
    };
    if !IRQ_BINDINGS.lock().can_push(adapter_index) {
        return false;
    }

    // The device-specific constructors masked and acknowledged their cause
    // registers, so unmasking the IOAPIC route cannot race an unregistered
    // handler. The binding is published before PCI/device interrupt enables.
    if crate::arch::x86_64::interrupts::ioapic::route(gsi, NIC_VECTOR, destination).is_none() {
        return false;
    }
    {
        let mut bindings = IRQ_BINDINGS.lock();
        if !bindings.push(IrqBinding {
            adapter_index,
            device: irq_device,
        }) {
            return false;
        }
    }

    let Some(address) = crate::devices::pci::PciAddress::new(
        device.address.bus(),
        device.address.device(),
        device.address.function(),
    ) else {
        return false;
    };
    let mut command = crate::devices::pci::PciCommand::from_bits_truncate(address.read_command());
    command.remove(crate::devices::pci::PciCommand::INTERRUPT_DISABLE);
    address.write_command(command.bits());
    irq_device.enable();
    ::log::debug!(
        "net: {} GSI {} selected for {}",
        if aml_gsi.is_some() {
            "ACPI _PRT"
        } else {
            "PCI Interrupt Line fallback"
        },
        gsi,
        device.address
    );
    true
}

/// Publish the autonomous network worker's stable task id for IRQ wakeups.
pub fn register_worker_task(task: crate::sched::TaskId) {
    NETWORK_WORKER_TASK.store(task.0, Ordering::Release);
}

/// Whether an interrupt arrived after or during the last bounded drain.
#[must_use]
pub fn interrupt_work_pending() -> bool {
    IRQ_PENDING.load(Ordering::Acquire) != 0
}

/// Sample interrupt/coalescing counters without touching adapter locks.
#[must_use]
pub fn irq_stats() -> IrqStats {
    IrqStats {
        interrupts: IRQ_COUNT.load(Ordering::Relaxed),
        claimed_devices: IRQ_CLAIMED_DEVICES.load(Ordering::Relaxed),
        worker_wakes: IRQ_WORKER_WAKES.load(Ordering::Relaxed),
        wake_contentions: IRQ_WAKE_CONTENTIONS.load(Ordering::Relaxed),
    }
}

fn mark_pending(adapter_index: usize) {
    if let Some(bit) = pending_bit(adapter_index) {
        IRQ_PENDING.fetch_or(bit, Ordering::Release);
    }
}

fn begin_irq_service(adapter_index: usize) {
    if let Some(bit) = pending_bit(adapter_index) {
        IRQ_PENDING.fetch_and(!bit, Ordering::AcqRel);
    }
}

fn rearm_allowed(pending: u64, bit: u64) -> bool {
    pending & bit == 0
}

fn should_rearm(adapter_index: usize) -> bool {
    pending_bit(adapter_index)
        .is_some_and(|bit| rearm_allowed(IRQ_PENDING.load(Ordering::Acquire), bit))
}

fn finish_irq_service(adapter_index: usize) {
    let bindings = IRQ_BINDINGS.lock();
    let Some(binding) = bindings.find(adapter_index) else {
        return;
    };
    // Holding the binding lock serializes this check-and-enable against the
    // hard handler. If that handler cannot take the lock it leaves the level
    // asserted, so the IOAPIC redelivers after this short section completes.
    if should_rearm(adapter_index) {
        binding.device.enable();
    }
}

fn wake_network_worker() -> bool {
    let task = NETWORK_WORKER_TASK.load(Ordering::Acquire);
    if task == 0 {
        return false;
    }
    match crate::sched::scheduler::wake_sleeping_task_from_irq(crate::sched::TaskId(task)) {
        crate::sched::scheduler::IrqWakeResult::Woken => {
            IRQ_WORKER_WAKES.fetch_add(1, Ordering::Relaxed);
            true
        },
        crate::sched::scheduler::IrqWakeResult::Contended => {
            IRQ_WAKE_CONTENTIONS.fetch_add(1, Ordering::Relaxed);
            false
        },
        crate::sched::scheduler::IrqWakeResult::NotSleeping => false,
    }
}

#[no_mangle]
extern "C" fn xenith_net_irq_rust() {
    IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    let mut pending = 0u64;
    let mut claimed = 0u64;
    // Never spin behind process context in a hard IRQ. Registration is a
    // boot-only operation, so contention here is exceptional; level INTx
    // remains asserted and is safely redelivered after EOI.
    if let Some(bindings) = IRQ_BINDINGS.try_lock() {
        for binding in bindings.iter() {
            if binding.device.acknowledge_and_mask() != 0 {
                if let Some(bit) = pending_bit(binding.adapter_index) {
                    pending |= bit;
                    claimed += 1;
                }
            }
        }
    }
    if pending != 0 {
        IRQ_PENDING.fetch_or(pending, Ordering::Release);
        IRQ_CLAIMED_DEVICES.fetch_add(claimed, Ordering::Relaxed);
    }
    if pending != 0 {
        let _ = wake_network_worker();
    }

    // Free the level-triggered vector and return. A successful non-blocking
    // wake set `need_resched`; the normal timer/return scheduling point will
    // dispatch the worker. The NIC hard IRQ never spins in `schedule_next`.
    crate::arch::x86_64::interrupts::apic::send_eoi();
}

#[must_use]
pub fn adapter_count() -> usize {
    ADAPTERS.lock().len()
}

#[must_use]
pub fn interface_id(adapter_index: usize) -> Option<u16> {
    let id = adapter_index.checked_add(1)?;
    u16::try_from(id).ok()
}

#[must_use]
pub fn adapter_info(index: usize) -> Option<AdapterInfo> {
    let adapters = ADAPTERS.lock();
    let adapter = adapters.get(index)?;
    Some(AdapterInfo {
        index,
        interface: interface_id(index)?,
        driver: adapter.driver_name(),
        mac: adapter.mac_address(),
        link_up: adapter.link_up(),
        mtu: adapter.mtu(),
    })
}

pub fn with_adapter<R>(index: usize, f: impl FnOnce(&mut dyn NetworkAdapter) -> R) -> Option<R> {
    let mut adapters = ADAPTERS.lock();
    let adapter = adapters.get_mut(index)?;
    Some(f(adapter))
}

pub fn transmit(index: usize, frame: &[u8]) -> Result<(), DriverError> {
    with_adapter(index, |adapter| adapter.transmit(frame)).ok_or(DriverError::InvalidAdapter)?
}

pub fn poll_receive(index: usize, output: &mut [u8]) -> Result<usize, DriverError> {
    with_adapter(index, |adapter| adapter.poll_receive(output))
        .ok_or(DriverError::InvalidAdapter)?
}

/// Transmit a frame produced by the IP stack through its selected interface.
pub fn transmit_outbound(frame: &OutboundFrame) -> Result<(), DriverError> {
    let index = frame
        .interface
        .checked_sub(1)
        .map(usize::from)
        .ok_or(DriverError::InvalidAdapter)?;
    transmit(index, &frame.bytes)
}

/// Poll every adapter and feed a bounded number of frames into the stack.
/// Interrupt routing is intentionally not required for this path, making it
/// usable during boot and as the fallback when an INTx/MSI route is absent.
pub fn poll_stack(now: u64, budget_per_adapter: usize) -> PollReport {
    let mut report = PollReport::default();
    if budget_per_adapter == 0 {
        return report;
    }
    let mut frame = [0u8; MAX_FRAME_LEN];
    let mut adapters = ADAPTERS.lock();
    for (index, adapter) in adapters.iter_mut().enumerate() {
        begin_irq_service(index);
        let Some(interface) = interface_id(index) else {
            report.driver_errors += 1;
            finish_irq_service(index);
            continue;
        };
        let mut drained = 0usize;
        for _ in 0..budget_per_adapter {
            let length = match adapter.poll_receive(&mut frame) {
                Ok(length) => length,
                Err(DriverError::NoPacket) => break,
                Err(_) => {
                    report.driver_errors += 1;
                    break;
                },
            };
            drained += 1;
            report.received += 1;
            match crate::net::ingest_frame(interface, &frame[..length], now) {
                Ok(IngressOutcome::Reply(reply)) => {
                    if reply.interface == interface && adapter.transmit(&reply.bytes).is_ok() {
                        report.replies += 1;
                    } else {
                        report.driver_errors += 1;
                    }
                },
                Ok(IngressOutcome::Delivered) => report.delivered += 1,
                Ok(IngressOutcome::Ignored | IngressOutcome::PortUnreachable(_)) => {
                    report.dropped += 1;
                },
                Err(_) => report.stack_errors += 1,
            }
        }
        // Reaching the budget is treated as possible residual work. One
        // harmless extra worker pass is preferable to rearming a level source
        // while descriptors remain queued and losing coalesced traffic.
        if drained == budget_per_adapter {
            mark_pending(index);
        }
        finish_irq_service(index);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intx_route_requires_a_real_pin_and_unreserved_firmware_line() {
        assert_eq!(fallback_intx_gsi(11, 1), Some(11));
        assert_eq!(fallback_intx_gsi(11, 4), Some(11));
        assert_eq!(fallback_intx_gsi(11, 0), None);
        assert_eq!(fallback_intx_gsi(11, 5), None);
        assert_eq!(fallback_intx_gsi(0, 1), None);
        assert_eq!(fallback_intx_gsi(0xff, 1), None);
        assert_eq!(
            fallback_intx_gsi(crate::devices::ps2::KEYBOARD_IRQ, 1),
            None
        );
        assert_eq!(fallback_intx_gsi(crate::devices::ps2::MOUSE_IRQ, 1), None);
    }

    #[test]
    fn shared_vector_does_not_overlap_fixed_kernel_vectors() {
        assert!(NIC_VECTOR >= crate::arch::x86_64::idt::EXCEPTION_VECTORS as u8);
        assert_ne!(NIC_VECTOR, crate::devices::ps2::KEYBOARD_VECTOR);
        assert_ne!(NIC_VECTOR, crate::devices::ps2::MOUSE_VECTOR);
        assert_ne!(NIC_VECTOR, crate::arch::x86_64::smp::RESCHEDULE_VECTOR);
        assert_ne!(NIC_VECTOR, crate::arch::x86_64::smp::TLB_SHOOTDOWN_VECTOR);
        assert_ne!(
            NIC_VECTOR,
            crate::arch::x86_64::interrupts::apic::TIMER_VECTOR
        );
    }

    #[test]
    fn pending_bitmap_bounds_and_coalescing_rearm_are_exact() {
        assert_eq!(pending_bit(0), Some(1));
        assert_eq!(pending_bit(63), Some(1u64 << 63));
        assert_eq!(pending_bit(64), None);
        let adapter_three = pending_bit(3).unwrap();
        assert!(!rearm_allowed(adapter_three, adapter_three));
        assert!(rearm_allowed(adapter_three, pending_bit(4).unwrap()));
    }
}

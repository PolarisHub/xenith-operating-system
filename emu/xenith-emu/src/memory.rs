//! Physical RAM, MMIO dispatch, paging, and dirty-page tracking.

use std::collections::{BTreeSet, VecDeque};

use crate::device::{Device, LocalApic};

const X2APIC_MSR_BASE: u32 = 0x800;
const X2APIC_MSR_END: u32 = 0x83f;
const X2APIC_EOI: u32 = 0x80b;
const X2APIC_ICR: u32 = 0x830;
const X2APIC_SELF_IPI: u32 = 0x83f;

/// Processor lifecycle transition requested through an APIC ICR write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApicEventKind {
    Init,
    Startup(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApicEvent {
    pub processor: usize,
    pub kind: ApicEventKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

/// Paging privilege used for a linear-memory access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Privilege {
    Supervisor,
    User,
}

/// Control-register state and privilege used for a page-table walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagingContext {
    pub cr0: u64,
    pub cr3: u64,
    pub efer: u64,
    pub privilege: Privilege,
}

impl PagingContext {
    #[must_use]
    pub const fn new(cr0: u64, cr3: u64, efer: u64, privilege: Privilege) -> Self {
        Self {
            cr0,
            cr3,
            efer,
            privilege,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryError {
    PhysicalOutOfBounds(u64),
    PageFault {
        address: u64,
        access: Access,
        reason: &'static str,
    },
}

pub struct MemoryBus {
    ram: Vec<u8>,
    devices: Vec<Box<dyn Device>>,
    dirty_pages: BTreeSet<u64>,
    active_processor: usize,
    local_apics: Vec<LocalApic>,
    apic_events: VecDeque<ApicEvent>,
}

impl MemoryBus {
    #[must_use]
    pub fn new(bytes: usize) -> Self {
        Self {
            ram: vec![0; bytes],
            devices: Vec::new(),
            dirty_pages: BTreeSet::new(),
            active_processor: 0,
            local_apics: vec![LocalApic::new(0)],
            apic_events: VecDeque::new(),
        }
    }

    /// Install one local APIC per emulated logical processor.
    pub(crate) fn configure_processors(&mut self, count: usize) {
        assert!(count != 0, "a machine needs at least one processor");
        self.local_apics = (0..count)
            .map(|index| LocalApic::new(index as u32))
            .collect();
        self.active_processor = 0;
        self.apic_events.clear();
    }

    pub(crate) fn select_processor(&mut self, processor: usize) {
        assert!(processor < self.local_apics.len());
        self.active_processor = processor;
    }

    pub(crate) fn take_apic_event(&mut self) -> Option<ApicEvent> {
        self.apic_events.pop_front()
    }

    /// Read a processor-local x2APIC MSR. Non-APIC indices return `None` so
    /// the CPU can fall back to its ordinary per-core MSR bank.
    pub(crate) fn read_x2apic_msr(&self, index: u32) -> Option<u64> {
        if !(X2APIC_MSR_BASE..=X2APIC_MSR_END).contains(&index) {
            return None;
        }
        let offset = ((index - X2APIC_MSR_BASE) << 4) as u16;
        Some(self.local_apics[self.active_processor].read_register(offset))
    }

    /// Apply a processor-local x2APIC MSR write and route any resulting IPI.
    pub(crate) fn write_x2apic_msr(&mut self, index: u32, value: u64) -> bool {
        if !(X2APIC_MSR_BASE..=X2APIC_MSR_END).contains(&index) {
            return false;
        }
        if index == X2APIC_EOI {
            self.local_apics[self.active_processor].end_of_interrupt();
            return true;
        }
        if index == X2APIC_SELF_IPI {
            self.local_apics[self.active_processor].queue_vector(value as u8);
            return true;
        }

        let offset = ((index - X2APIC_MSR_BASE) << 4) as u16;
        self.local_apics[self.active_processor].write_register(offset, value);
        if index == X2APIC_ICR {
            self.route_icr(value);
        }
        true
    }

    fn route_icr(&mut self, value: u64) {
        let shorthand = (value >> 18) & 0b11;
        let destination = (value >> 32) as u32;
        let source = self.active_processor;
        let targets: Vec<usize> = match shorthand {
            0 => self
                .local_apics
                .iter()
                .position(|apic| apic.apic_id() == destination)
                .into_iter()
                .collect(),
            1 => vec![source],
            2 => (0..self.local_apics.len()).collect(),
            3 => (0..self.local_apics.len())
                .filter(|processor| *processor != source)
                .collect(),
            _ => unreachable!(),
        };
        let vector = value as u8;
        match (value >> 8) & 0b111 {
            // Fixed and lowest-priority delivery. For the latter, a physical
            // destination resolves to one target in this bounded topology.
            0 | 1 => {
                for target in targets {
                    self.local_apics[target].queue_vector(vector);
                }
            },
            // NMI. Xenith does not currently issue one, but vector 2 keeps
            // the route observable instead of silently dropping it.
            4 => {
                for target in targets {
                    self.local_apics[target].queue_vector(2);
                }
            },
            5 => {
                for processor in targets {
                    self.local_apics[processor].reset();
                    self.apic_events.push_back(ApicEvent {
                        processor,
                        kind: ApicEventKind::Init,
                    });
                }
            },
            6 => {
                for processor in targets {
                    self.apic_events.push_back(ApicEvent {
                        processor,
                        kind: ApicEventKind::Startup(vector),
                    });
                }
            },
            // SMI and ExtINT have no host-side source in this interpreter.
            _ => {},
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ram.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ram.is_empty()
    }

    pub fn attach<D: Device + 'static>(&mut self, device: D) {
        self.devices.push(Box::new(device));
    }

    pub fn tick(&mut self, cycles: u64) {
        self.local_apics[self.active_processor].advance(cycles);
        for device in &mut self.devices {
            device.tick(cycles);
        }
    }

    pub fn next_interrupt(&mut self) -> Option<u8> {
        if let Some(vector) = self.local_apics[self.active_processor].next_interrupt() {
            return Some(vector);
        }
        // Platform interrupts are initially routed to the BSP. APs only
        // consume their local timer and IPIs until an emulated IOAPIC route
        // explicitly grows a destination model.
        if self.active_processor != 0 {
            return None;
        }
        let source_vector = self
            .devices
            .iter_mut()
            .find_map(|device| device.interrupt())?;
        let Some(irq) = source_vector.checked_sub(0x20) else {
            return Some(source_vector);
        };
        let route = self
            .devices
            .iter()
            .find_map(|device| device.ioapic_route(irq));
        let Some(route) = route else {
            // Standalone CPU/device tests intentionally have no I/O APIC.
            return Some(source_vector);
        };
        if route.masked {
            return None;
        }
        let target = self
            .local_apics
            .iter()
            .position(|apic| apic.apic_id() == u32::from(route.destination))?;
        self.local_apics[target].queue_vector(route.vector);
        (target == self.active_processor)
            .then(|| self.local_apics[target].next_interrupt())
            .flatten()
    }

    /// Queue raw keyboard set-1 scancodes on the attached 8042 controller.
    ///
    /// Returns `false` only when this bus has no PS/2-capable device. The
    /// controller itself may discard input while its first port or keyboard
    /// scanning is disabled, matching the guest-programmed device state.
    pub fn inject_ps2_scancodes(&mut self, scancodes: &[u8]) -> bool {
        self.devices
            .iter_mut()
            .any(|device| device.inject_ps2_scancodes(scancodes))
    }

    /// Whether an attached PS/2 keyboard currently accepts interrupt-driven
    /// input according to guest-programmed controller state.
    #[must_use]
    pub fn ps2_keyboard_ready(&self) -> bool {
        self.devices
            .iter()
            .find_map(|device| device.ps2_keyboard_ready())
            .unwrap_or(false)
    }

    pub fn read_port(&mut self, port: u16, size: u8) -> u32 {
        self.devices
            .iter_mut()
            .find_map(|device| device.read_port(port, size))
            .unwrap_or(u32::MAX)
    }

    pub fn write_port(&mut self, port: u16, size: u8, value: u32) {
        for device in &mut self.devices {
            if device.write_port(port, size, value) {
                return;
            }
        }
    }

    pub fn read_physical(&mut self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        if let Some(value) =
            self.local_apics[self.active_processor].read_mmio(address, output.len() as u8)
        {
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = (value >> (index * 8)) as u8;
            }
            return Ok(());
        }
        if let Some(value) = self
            .devices
            .iter_mut()
            .find_map(|device| device.read_mmio(address, output.len() as u8))
        {
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = (value >> (index * 8)) as u8;
            }
            return Ok(());
        }
        let start =
            usize::try_from(address).map_err(|_| MemoryError::PhysicalOutOfBounds(address))?;
        let end = start
            .checked_add(output.len())
            .ok_or(MemoryError::PhysicalOutOfBounds(address))?;
        let source = self
            .ram
            .get(start..end)
            .ok_or(MemoryError::PhysicalOutOfBounds(address))?;
        output.copy_from_slice(source);
        Ok(())
    }

    pub fn write_physical(&mut self, address: u64, input: &[u8]) -> Result<(), MemoryError> {
        let mut value = 0u64;
        if input.len() <= 8 {
            for (index, byte) in input.iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
            if self.local_apics[self.active_processor].write_mmio(address, input.len() as u8, value)
            {
                return Ok(());
            }
            if self
                .devices
                .iter_mut()
                .any(|device| device.write_mmio(address, input.len() as u8, value))
            {
                return Ok(());
            }
        }
        let start =
            usize::try_from(address).map_err(|_| MemoryError::PhysicalOutOfBounds(address))?;
        let end = start
            .checked_add(input.len())
            .ok_or(MemoryError::PhysicalOutOfBounds(address))?;
        let destination = self
            .ram
            .get_mut(start..end)
            .ok_or(MemoryError::PhysicalOutOfBounds(address))?;
        destination.copy_from_slice(input);
        if !input.is_empty() {
            let first = address >> 12;
            let last = (address + input.len() as u64 - 1) >> 12;
            self.dirty_pages.extend(first..=last);
        }
        Ok(())
    }

    pub fn read_u64_physical(&self, address: u64) -> Result<u64, MemoryError> {
        let start =
            usize::try_from(address).map_err(|_| MemoryError::PhysicalOutOfBounds(address))?;
        let bytes = self
            .ram
            .get(start..start + 8)
            .ok_or(MemoryError::PhysicalOutOfBounds(address))?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("eight-byte slice"),
        ))
    }

    pub fn write_u64_physical(&mut self, address: u64, value: u64) -> Result<(), MemoryError> {
        self.write_physical(address, &value.to_le_bytes())
    }

    pub fn translate(
        &self,
        linear: u64,
        paging: PagingContext,
        access: Access,
    ) -> Result<u64, MemoryError> {
        if paging.cr0 & (1 << 31) == 0 {
            return Ok(linear);
        }
        let indices = [
            (linear >> 39) & 0x1FF,
            (linear >> 30) & 0x1FF,
            (linear >> 21) & 0x1FF,
            (linear >> 12) & 0x1FF,
        ];
        let mut table = paging.cr3 & 0x000F_FFFF_FFFF_F000;
        let mut writable = true;
        let mut executable = true;
        for (level, index) in indices.into_iter().enumerate() {
            let entry = self.read_u64_physical(table + index * 8)?;
            if entry & 1 == 0 {
                return Err(MemoryError::PageFault {
                    address: linear,
                    access,
                    reason: "not present",
                });
            }
            if paging.privilege == Privilege::User && entry & 4 == 0 {
                return Err(MemoryError::PageFault {
                    address: linear,
                    access,
                    reason: "supervisor-only",
                });
            }
            writable &= entry & 2 != 0;
            if paging.efer & (1 << 11) != 0 {
                executable &= entry & (1 << 63) == 0;
            }
            if access == Access::Write && !writable {
                return Err(MemoryError::PageFault {
                    address: linear,
                    access,
                    reason: "read-only",
                });
            }
            if access == Access::Execute && !executable {
                return Err(MemoryError::PageFault {
                    address: linear,
                    access,
                    reason: "no-execute",
                });
            }
            let address = entry & 0x000F_FFFF_FFFF_F000;
            if entry & (1 << 7) != 0 && level == 1 {
                return Ok((address & !((1 << 30) - 1)) | (linear & ((1 << 30) - 1)));
            }
            if entry & (1 << 7) != 0 && level == 2 {
                return Ok((address & !((1 << 21) - 1)) | (linear & ((1 << 21) - 1)));
            }
            if level == 3 {
                return Ok(address | (linear & 0xFFF));
            }
            table = address;
        }
        unreachable!()
    }

    pub fn read_linear(
        &mut self,
        linear: u64,
        output: &mut [u8],
        paging: PagingContext,
        access: Access,
    ) -> Result<(), MemoryError> {
        if output.is_empty() {
            return Ok(());
        }
        let last = linear
            .checked_add(output.len() as u64 - 1)
            .ok_or(MemoryError::PageFault {
                address: linear,
                access,
                reason: "linear range overflow",
            })?;
        if linear >> 12 == last >> 12 {
            let physical = self.translate(linear, paging, access)?;
            return self.read_physical(physical, output);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            let physical = self.translate(linear + index as u64, paging, access)?;
            self.read_physical(physical, core::slice::from_mut(byte))?;
        }
        Ok(())
    }

    pub fn write_linear(
        &mut self,
        linear: u64,
        input: &[u8],
        paging: PagingContext,
    ) -> Result<(), MemoryError> {
        if input.is_empty() {
            return Ok(());
        }
        let last = linear
            .checked_add(input.len() as u64 - 1)
            .ok_or(MemoryError::PageFault {
                address: linear,
                access: Access::Write,
                reason: "linear range overflow",
            })?;
        if linear >> 12 == last >> 12 {
            let physical = self.translate(linear, paging, Access::Write)?;
            return self.write_physical(physical, input);
        }
        for (index, byte) in input.iter().enumerate() {
            let physical = self.translate(linear + index as u64, paging, Access::Write)?;
            self.write_physical(physical, core::slice::from_ref(byte))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn take_dirty_pages(&mut self) -> Vec<u64> {
        core::mem::take(&mut self.dirty_pages).into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CR0_PG: u64 = 1 << 31;
    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const USER: u64 = 1 << 2;

    fn paged_bus() -> MemoryBus {
        let mut bus = MemoryBus::new(0x6000);
        for (entry_address, next_table) in [(0x1000, 0x2000), (0x2000, 0x3000), (0x3000, 0x4000)] {
            bus.write_u64_physical(entry_address, next_table | PRESENT | WRITABLE | USER)
                .expect("install non-leaf page-table entry");
        }
        bus.write_u64_physical(0x4000, 0x5000 | PRESENT | WRITABLE | USER)
            .expect("install leaf page-table entry");
        bus
    }

    #[test]
    fn user_access_requires_user_permission_at_every_level() {
        let paging = PagingContext::new(CR0_PG, 0x1000, 0, Privilege::User);
        for entry_address in [0x1000, 0x2000, 0x3000, 0x4000] {
            for access in [Access::Read, Access::Write, Access::Execute] {
                let mut bus = paged_bus();
                let entry = bus
                    .read_u64_physical(entry_address)
                    .expect("read page-table entry");
                bus.write_u64_physical(entry_address, entry & !USER)
                    .expect("make one paging level supervisor-only");

                assert_eq!(
                    bus.translate(0, paging, access),
                    Err(MemoryError::PageFault {
                        address: 0,
                        access,
                        reason: "supervisor-only",
                    })
                );
            }
        }
    }

    #[test]
    fn supervisor_access_can_use_supervisor_pages() {
        let mut bus = paged_bus();
        let paging = PagingContext::new(CR0_PG, 0x1000, 0, Privilege::Supervisor);
        for entry_address in [0x1000, 0x2000, 0x3000, 0x4000] {
            let entry = bus
                .read_u64_physical(entry_address)
                .expect("read page-table entry");
            bus.write_u64_physical(entry_address, entry & !USER)
                .expect("make paging level supervisor-only");
        }

        for access in [Access::Read, Access::Write, Access::Execute] {
            assert_eq!(bus.translate(0x123, paging, access), Ok(0x5123));
        }
    }

    #[test]
    fn x2apic_icr_routes_init_startup_and_fixed_ipis() {
        let mut bus = MemoryBus::new(0x1000);
        bus.configure_processors(2);
        bus.select_processor(0);

        assert!(bus.write_x2apic_msr(X2APIC_ICR, (1_u64 << 32) | (5 << 8)));
        assert_eq!(
            bus.take_apic_event(),
            Some(ApicEvent {
                processor: 1,
                kind: ApicEventKind::Init,
            })
        );
        assert!(bus.write_x2apic_msr(X2APIC_ICR, (1_u64 << 32) | (6 << 8) | 0x80));
        assert_eq!(
            bus.take_apic_event(),
            Some(ApicEvent {
                processor: 1,
                kind: ApicEventKind::Startup(0x80),
            })
        );

        assert!(bus.write_x2apic_msr(X2APIC_ICR, (1_u64 << 32) | 0x44));
        bus.select_processor(1);
        assert_eq!(bus.next_interrupt(), Some(0x44));
        assert!(bus.write_x2apic_msr(X2APIC_EOI, 0));
    }

    #[test]
    fn x2apic_timer_state_is_processor_local() {
        let mut bus = MemoryBus::new(0x1000);
        bus.configure_processors(2);
        bus.select_processor(1);
        assert!(bus.write_x2apic_msr(0x80f, 0x1ff));
        assert!(bus.write_x2apic_msr(0x83e, 0x0b));
        assert!(bus.write_x2apic_msr(0x832, 0x41));
        assert!(bus.write_x2apic_msr(0x838, 1));
        bus.tick(2);
        assert_eq!(bus.next_interrupt(), Some(0x41));

        bus.select_processor(0);
        assert_eq!(bus.read_x2apic_msr(0x839), Some(0));
        assert_eq!(bus.next_interrupt(), None);
    }
}

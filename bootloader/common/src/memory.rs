//! Fixed-capacity memory-map construction with reservation carving.

use xenith_abi::{BootMemoryKind, XenithMemoryRegion};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapError {
    Capacity,
    AddressOverflow,
    UnsortedReservations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    pub base: u64,
    pub length: u64,
    pub kind: BootMemoryKind,
}

impl Reservation {
    pub const fn new(base: u64, length: u64, kind: BootMemoryKind) -> Self {
        Self { base, length, kind }
    }

    fn end(self) -> Result<u64, MemoryMapError> {
        self.base
            .checked_add(self.length)
            .ok_or(MemoryMapError::AddressOverflow)
    }
}

pub fn append_region(
    output: &mut [XenithMemoryRegion],
    used: &mut usize,
    base: u64,
    length: u64,
    kind: BootMemoryKind,
) -> Result<(), MemoryMapError> {
    if length == 0 {
        return Ok(());
    }
    base.checked_add(length)
        .ok_or(MemoryMapError::AddressOverflow)?;
    if let Some(previous) = used.checked_sub(1).and_then(|index| output.get_mut(index)) {
        if previous.kind == kind && previous.base.checked_add(previous.length) == Some(base) {
            previous.length = previous
                .length
                .checked_add(length)
                .ok_or(MemoryMapError::AddressOverflow)?;
            return Ok(());
        }
    }
    let slot = output.get_mut(*used).ok_or(MemoryMapError::Capacity)?;
    *slot = XenithMemoryRegion {
        base,
        length,
        kind,
        reserved: 0,
    };
    *used += 1;
    Ok(())
}

pub fn append_region_with_reservations(
    output: &mut [XenithMemoryRegion],
    used: &mut usize,
    base: u64,
    length: u64,
    kind: BootMemoryKind,
    reservations: &[Reservation],
) -> Result<(), MemoryMapError> {
    if kind != BootMemoryKind::Usable || length == 0 {
        return append_region(output, used, base, length, kind);
    }
    let end = base
        .checked_add(length)
        .ok_or(MemoryMapError::AddressOverflow)?;
    let mut last_reservation_end = 0;
    let mut cursor = base;
    for &reservation in reservations {
        let reservation_end = reservation.end()?;
        if reservation.base < last_reservation_end {
            return Err(MemoryMapError::UnsortedReservations);
        }
        last_reservation_end = reservation_end;
        if reservation.length == 0 || reservation_end <= cursor || reservation.base >= end {
            continue;
        }
        let overlap_start = reservation.base.max(cursor);
        let overlap_end = reservation_end.min(end);
        append_region(
            output,
            used,
            cursor,
            overlap_start.saturating_sub(cursor),
            BootMemoryKind::Usable,
        )?;
        append_region(
            output,
            used,
            overlap_start,
            overlap_end - overlap_start,
            reservation.kind,
        )?;
        cursor = overlap_end;
    }
    append_region(
        output,
        used,
        cursor,
        end.saturating_sub(cursor),
        BootMemoryKind::Usable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: XenithMemoryRegion = XenithMemoryRegion {
        base: 0,
        length: 0,
        kind: BootMemoryKind::Reserved,
        reserved: 0,
    };

    #[test]
    fn carves_kernel_and_initrd_from_usable_memory() {
        let reservations = [
            Reservation::new(0, 0x10_0000, BootMemoryKind::Reserved),
            Reservation::new(0x20_0000, 0x10_0000, BootMemoryKind::KernelAndModules),
            Reservation::new(0x40_0000, 0x08_0000, BootMemoryKind::KernelAndModules),
        ];
        let mut output = [EMPTY; 8];
        let mut used = 0;
        append_region_with_reservations(
            &mut output,
            &mut used,
            0,
            0x50_0000,
            BootMemoryKind::Usable,
            &reservations,
        )
        .unwrap();
        assert_eq!(used, 6);
        assert_eq!(output[0].kind, BootMemoryKind::Reserved);
        assert_eq!(output[1].base, 0x10_0000);
        assert_eq!(output[2].kind, BootMemoryKind::KernelAndModules);
        assert_eq!(output[5].base, 0x48_0000);
    }

    #[test]
    fn adjacent_regions_are_coalesced() {
        let mut output = [EMPTY; 2];
        let mut used = 0;
        append_region(&mut output, &mut used, 0, 10, BootMemoryKind::Reserved).unwrap();
        append_region(&mut output, &mut used, 10, 10, BootMemoryKind::Reserved).unwrap();
        assert_eq!(used, 1);
        assert_eq!(output[0].length, 20);
    }
}

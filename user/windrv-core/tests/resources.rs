use core::mem::size_of;

use xenith_windrv_core::{
    HardwareGrant, HardwareGrantTable, HardwareResource, ResourceError, ResourceId, ResourceRights,
    MAX_DMA_TRANSFER_BYTES, MAX_HARDWARE_GRANTS, MAX_MMIO_GRANT_BYTES,
};

#[test]
fn resource_capacities_are_validated() {
    assert!(matches!(
        HardwareGrantTable::<0>::try_new(),
        Err(ResourceError::InvalidCapacity { .. })
    ));
    assert!(HardwareGrantTable::<MAX_HARDWARE_GRANTS>::try_new().is_ok());
    assert!(matches!(
        HardwareGrantTable::<{ MAX_HARDWARE_GRANTS + 1 }>::try_new(),
        Err(ResourceError::InvalidCapacity {
            capacity,
            maximum: MAX_HARDWARE_GRANTS,
        }) if capacity == MAX_HARDWARE_GRANTS + 1
    ));
    assert!(
        size_of::<HardwareGrantTable<MAX_HARDWARE_GRANTS>>() <= 64 * 1024,
        "maximum inline grant table must stay below the audited stack budget"
    );
}

#[test]
fn io_port_ranges_and_rights_are_exact() {
    let valid = HardwareGrant {
        resource: HardwareResource::IoPort {
            start: 0xfff0,
            length: 16,
        },
        rights: ResourceRights::READ.union(ResourceRights::WRITE),
    };
    assert_eq!(valid.validate(), Ok(valid));
    assert!(matches!(
        HardwareGrant {
            resource: HardwareResource::IoPort {
                start: 0xffff,
                length: 2,
            },
            rights: ResourceRights::READ,
        }
        .validate(),
        Err(ResourceError::InvalidRange)
    ));
    assert!(matches!(
        HardwareGrant {
            resource: HardwareResource::IoPort {
                start: 0x3f8,
                length: 8,
            },
            rights: ResourceRights::MAP,
        }
        .validate(),
        Err(ResourceError::InvalidRights)
    ));
    assert!(matches!(
        HardwareGrant {
            resource: HardwareResource::IoPort {
                start: 1,
                length: u32::MAX,
            },
            rights: ResourceRights::READ,
        }
        .validate(),
        Err(ResourceError::InvalidRange)
    ));
}

#[test]
fn mmio_grants_require_page_bounds_and_map_right() {
    let valid = HardwareGrant {
        resource: HardwareResource::Mmio {
            physical_base: 0xf000_0000,
            length: 0x20_0000,
        },
        rights: ResourceRights::MAP.union(ResourceRights::READ),
    };
    assert_eq!(valid.validate(), Ok(valid));
    for bad in [
        HardwareGrant {
            resource: HardwareResource::Mmio {
                physical_base: 1,
                length: 4096,
            },
            rights: ResourceRights::MAP,
        },
        HardwareGrant {
            resource: HardwareResource::Mmio {
                physical_base: 0x1000,
                length: MAX_MMIO_GRANT_BYTES + 4096,
            },
            rights: ResourceRights::MAP,
        },
        HardwareGrant {
            resource: HardwareResource::Mmio {
                physical_base: 0x1000,
                length: 4096,
            },
            rights: ResourceRights::READ,
        },
    ] {
        assert!(bad.validate().is_err());
    }
}

#[test]
fn interrupt_and_dma_kinds_cannot_gain_unrelated_rights() {
    assert!(HardwareGrant {
        resource: HardwareResource::Interrupt {
            vector: 0x40,
            level_triggered: true,
            active_low: true,
        },
        rights: ResourceRights::ACK_INTERRUPT,
    }
    .validate()
    .is_ok());
    assert!(HardwareGrant {
        resource: HardwareResource::Interrupt {
            vector: 14,
            level_triggered: false,
            active_low: false,
        },
        rights: ResourceRights::ACK_INTERRUPT,
    }
    .validate()
    .is_err());
    assert!(HardwareGrant {
        resource: HardwareResource::DmaDomain {
            maximum_address: u64::MAX,
            maximum_transfer: MAX_DMA_TRANSFER_BYTES,
            coherent: true,
        },
        rights: ResourceRights::DMA,
    }
    .validate()
    .is_ok());
}

#[test]
fn grants_attenuate_rights_and_revoke_stale_ids() {
    let mut table = HardwareGrantTable::<1>::try_new().unwrap();
    let grant = HardwareGrant {
        resource: HardwareResource::IoPort {
            start: 0x3f8,
            length: 8,
        },
        rights: ResourceRights::READ,
    };
    let old = table.grant(grant).unwrap();
    assert_eq!(table.reference(old, ResourceRights::READ), Ok(grant));
    assert!(matches!(
        table.reference(old, ResourceRights::WRITE),
        Err(ResourceError::AccessDenied { .. })
    ));
    assert_eq!(
        table.reference(old, ResourceRights::NONE),
        Err(ResourceError::InvalidRights)
    );
    assert_eq!(
        table.reference(old, ResourceRights::from_bits(0x80)),
        Err(ResourceError::InvalidRights)
    );
    assert_eq!(table.revoke(old), Ok(grant));
    assert_eq!(
        table.reference(old, ResourceRights::READ),
        Err(ResourceError::InvalidResource)
    );
    let replacement = table.grant(grant).unwrap();
    assert_ne!(old, replacement);
    assert_eq!(
        table.revoke(ResourceId::from_raw(u32::MAX)),
        Err(ResourceError::InvalidResource)
    );
}

#[test]
fn returned_grants_carry_only_the_rights_authorized_for_that_operation() {
    let mut table = HardwareGrantTable::<2>::try_new().unwrap();
    let ports = table
        .grant(HardwareGrant {
            resource: HardwareResource::IoPort {
                start: 0x3f8,
                length: 8,
            },
            rights: ResourceRights::READ.union(ResourceRights::WRITE),
        })
        .unwrap();
    let read = table.reference(ports, ResourceRights::READ).unwrap();
    assert_eq!(read.rights, ResourceRights::READ);

    let mmio = table
        .grant(HardwareGrant {
            resource: HardwareResource::Mmio {
                physical_base: 0x1000,
                length: 0x1000,
            },
            rights: ResourceRights::MAP
                .union(ResourceRights::READ)
                .union(ResourceRights::WRITE),
        })
        .unwrap();
    assert_eq!(
        table.reference(mmio, ResourceRights::READ),
        Err(ResourceError::InvalidRights)
    );
    let mapped_read = ResourceRights::MAP.union(ResourceRights::READ);
    assert_eq!(
        table.reference(mmio, mapped_read).unwrap().rights,
        mapped_read
    );
}

#[test]
fn every_rights_byte_is_rejected_or_accepted_by_exact_kind_policy() {
    let resources = [
        (
            HardwareResource::IoPort {
                start: 0x3f8,
                length: 8,
            },
            0b0_0011_u8,
            0_u8,
        ),
        (
            HardwareResource::Mmio {
                physical_base: 0x1000,
                length: 0x1000,
            },
            0b0_0111_u8,
            ResourceRights::MAP.bits(),
        ),
        (
            HardwareResource::Interrupt {
                vector: 0x40,
                level_triggered: false,
                active_low: false,
            },
            ResourceRights::ACK_INTERRUPT.bits(),
            ResourceRights::ACK_INTERRUPT.bits(),
        ),
        (
            HardwareResource::DmaDomain {
                maximum_address: u64::MAX,
                maximum_transfer: 4096,
                coherent: false,
            },
            ResourceRights::DMA.bits(),
            ResourceRights::DMA.bits(),
        ),
    ];

    for (resource_index, (resource, allowed, required)) in resources.into_iter().enumerate() {
        for raw in u8::MIN..=u8::MAX {
            let valid_subset = raw != 0 && raw & !allowed == 0;
            let has_required = raw & required == required;
            let has_mmio_access = resource_index != 1 || raw & 0b11 != 0;
            let exact_required = resource_index < 2 || raw == required;
            let expected = valid_subset && has_required && has_mmio_access && exact_required;
            let result = HardwareGrant {
                resource,
                rights: ResourceRights::from_bits(raw),
            }
            .validate();
            assert_eq!(
                result.is_ok(),
                expected,
                "resource {resource_index}, rights {raw:#04x}"
            );
        }
    }
}

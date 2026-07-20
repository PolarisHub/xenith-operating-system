use core::mem::size_of;

use xenith_windrv_core::{
    DriverId, DriverObject, DriverRegistry, MajorFunction, RegistryError, MAX_DEVICE_OBJECTS,
    MAX_DEVICE_STACK_DEPTH, MAX_DRIVER_OBJECTS,
};
use xenith_winhost_core::RUNTIME_USER_ADDRESS_LIMIT;

fn driver(base: u64) -> DriverObject {
    let mut object = DriverObject::new(base, 0x4000, base + 0x100).unwrap();
    object
        .set_dispatch(MajorFunction::Create, base + 0x200)
        .unwrap();
    object
        .set_dispatch(MajorFunction::DeviceControl, base + 0x300)
        .unwrap();
    object
}

#[test]
fn driver_callbacks_must_stay_inside_the_image() {
    assert_eq!(
        DriverObject::new(0x1000, 0x1000, 0x3000),
        Err(RegistryError::AddressOutsideImage { address: 0x3000 })
    );
    let mut object = driver(0x10_0000);
    assert_eq!(
        object.set_dispatch(MajorFunction::Read, 0x20_0000),
        Err(RegistryError::AddressOutsideImage { address: 0x20_0000 })
    );
    object.set_dispatch(MajorFunction::Read, 0).unwrap();
    assert_eq!(object.dispatch(MajorFunction::Read), None);

    let base = RUNTIME_USER_ADDRESS_LIMIT - 0x2000;
    assert!(DriverObject::new(base, 0x2000, base).is_ok());
    assert_eq!(
        DriverObject::new(base, 0x2000, RUNTIME_USER_ADDRESS_LIMIT),
        Err(RegistryError::AddressOutsideImage {
            address: RUNTIME_USER_ADDRESS_LIMIT,
        })
    );
    assert_eq!(
        DriverObject::new(base, 0x3000, base),
        Err(RegistryError::InvalidImageRange)
    );
    assert_eq!(
        DriverObject::new(
            RUNTIME_USER_ADDRESS_LIMIT,
            0x1000,
            RUNTIME_USER_ADDRESS_LIMIT
        ),
        Err(RegistryError::InvalidImageRange)
    );
    assert_eq!(
        DriverObject::new(u64::MAX - 0xfff, 0x2000, u64::MAX - 0xfff),
        Err(RegistryError::InvalidImageRange)
    );
}

#[test]
fn capacities_are_checked_before_use() {
    assert!(matches!(
        DriverRegistry::<0, 1>::try_new(),
        Err(RegistryError::InvalidCapacity { capacity: 0, .. })
    ));
    assert!(matches!(
        DriverRegistry::<1, 0>::try_new(),
        Err(RegistryError::InvalidCapacity { capacity: 0, .. })
    ));
    assert!(DriverRegistry::<MAX_DRIVER_OBJECTS, MAX_DEVICE_OBJECTS>::try_new().is_ok());
    assert!(matches!(
        DriverRegistry::<{ MAX_DRIVER_OBJECTS + 1 }, 1>::try_new(),
        Err(RegistryError::InvalidCapacity {
            capacity,
            maximum: MAX_DRIVER_OBJECTS,
        }) if capacity == MAX_DRIVER_OBJECTS + 1
    ));
    assert!(matches!(
        DriverRegistry::<1, { MAX_DEVICE_OBJECTS + 1 }>::try_new(),
        Err(RegistryError::InvalidCapacity {
            capacity,
            maximum: MAX_DEVICE_OBJECTS,
        }) if capacity == MAX_DEVICE_OBJECTS + 1
    ));
    assert!(
        size_of::<DriverRegistry<MAX_DRIVER_OBJECTS, MAX_DEVICE_OBJECTS>>() <= 128 * 1024,
        "maximum inline registry must stay below the audited stack budget"
    );
}

#[test]
fn registration_dispatch_and_teardown_are_generation_safe() {
    let mut registry = DriverRegistry::<2, 3>::try_new().unwrap();
    let owner = registry.register_driver(driver(0x40_0000)).unwrap();
    let device = registry.create_device(owner, None, 0x22, 0).unwrap();
    assert_eq!(registry.driver_count(), 1);
    assert_eq!(registry.device_count(), 1);
    assert_eq!(
        registry
            .dispatch_address(device, MajorFunction::DeviceControl)
            .unwrap(),
        0x40_0300
    );
    assert_eq!(
        registry.dispatch_address(device, MajorFunction::Read),
        Err(RegistryError::NoDispatch)
    );
    assert_eq!(
        registry.unregister_driver(owner),
        Err(RegistryError::DriverBusy)
    );

    registry.remove_device(device).unwrap();
    registry.unregister_driver(owner).unwrap();
    assert_eq!(registry.driver(owner), Err(RegistryError::InvalidDriver));
    assert_eq!(registry.device(device), Err(RegistryError::InvalidDevice));

    let replacement = registry.register_driver(driver(0x50_0000)).unwrap();
    assert_ne!(replacement, owner);
    assert_eq!(registry.driver(owner), Err(RegistryError::InvalidDriver));
}

#[test]
fn removing_lower_device_requires_top_down_teardown() {
    let mut registry = DriverRegistry::<1, 2>::try_new().unwrap();
    let owner = registry.register_driver(driver(0x60_0000)).unwrap();
    let lower = registry.create_device(owner, None, 1, 0).unwrap();
    let upper = registry.create_device(owner, Some(lower), 1, 0).unwrap();
    assert_eq!(registry.stack_depth(upper), Ok(2));
    let plan = registry.plan_stack(upper).unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan.top(), Some(upper));
    assert_eq!(plan.get(1), Some(lower));
    assert_eq!(plan.get(2), None);
    assert_eq!(
        registry.remove_device(lower),
        Err(RegistryError::DeviceBusy)
    );
    registry.remove_device(upper).unwrap();
    registry.remove_device(lower).unwrap();
}

#[test]
fn attach_rejects_cycles_and_double_attachment() {
    let mut registry = DriverRegistry::<1, 3>::try_new().unwrap();
    let owner = registry.register_driver(driver(0x70_0000)).unwrap();
    let first = registry.create_device(owner, None, 1, 0).unwrap();
    let second = registry.create_device(owner, None, 1, 0).unwrap();
    registry.attach_device(first, second).unwrap();
    assert_eq!(
        registry.attach_device(first, second),
        Err(RegistryError::AlreadyAttached)
    );
    assert_eq!(
        registry.attach_device(second, first),
        Err(RegistryError::AttachmentCycle)
    );
    assert_eq!(registry.detach_device(first), Ok(Some(second)));
    assert_eq!(registry.detach_device(first), Ok(None));
}

#[test]
fn a_device_stack_is_linear_and_rejects_branching() {
    let mut registry = DriverRegistry::<1, 4>::try_new().unwrap();
    let owner = registry.register_driver(driver(0x71_0000)).unwrap();
    let lower = registry.create_device(owner, None, 1, 0).unwrap();
    let first_upper = registry.create_device(owner, Some(lower), 1, 0).unwrap();

    assert_eq!(
        registry.create_device(owner, Some(lower), 1, 0),
        Err(RegistryError::DeviceBusy)
    );
    let second_upper = registry.create_device(owner, None, 1, 0).unwrap();
    assert_eq!(
        registry.attach_device(second_upper, lower),
        Err(RegistryError::DeviceBusy)
    );
    assert_eq!(
        registry.plan_stack(first_upper).unwrap().get(1),
        Some(lower)
    );
    assert_eq!(registry.device(second_upper).unwrap().lower_device, None);
}

#[test]
fn device_stack_depth_is_hard_bounded() {
    let mut registry = DriverRegistry::<1, 12>::try_new().unwrap();
    let owner = registry.register_driver(driver(0x80_0000)).unwrap();
    let mut top = registry.create_device(owner, None, 1, 0).unwrap();
    for _ in 1..MAX_DEVICE_STACK_DEPTH {
        top = registry.create_device(owner, Some(top), 1, 0).unwrap();
    }
    assert_eq!(registry.stack_depth(top), Ok(MAX_DEVICE_STACK_DEPTH));
    assert_eq!(
        registry.create_device(owner, Some(top), 1, 0),
        Err(RegistryError::StackTooDeep)
    );
}

#[test]
fn attach_path_accepts_exact_limit_and_rejects_limit_plus_one() {
    let mut registry = DriverRegistry::<1, 10>::try_new().unwrap();
    let owner = registry.register_driver(driver(0x81_0000)).unwrap();
    let mut top = registry.create_device(owner, None, 1, 0).unwrap();
    for _ in 1..MAX_DEVICE_STACK_DEPTH {
        let next = registry.create_device(owner, None, 1, 0).unwrap();
        registry.attach_device(next, top).unwrap();
        top = next;
    }
    assert_eq!(registry.stack_depth(top), Ok(MAX_DEVICE_STACK_DEPTH));

    let overflow = registry.create_device(owner, None, 1, 0).unwrap();
    assert_eq!(
        registry.attach_device(overflow, top),
        Err(RegistryError::StackTooDeep)
    );
    assert_eq!(registry.device(overflow).unwrap().lower_device, None);
}

#[test]
fn malformed_boundary_ids_are_rejected() {
    let registry = DriverRegistry::<1, 1>::try_new().unwrap();
    for raw in [0, 1, u32::MAX] {
        assert_eq!(
            registry.driver(DriverId::from_raw(raw)),
            Err(RegistryError::InvalidDriver)
        );
    }
}

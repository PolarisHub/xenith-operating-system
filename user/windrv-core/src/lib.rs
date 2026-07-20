//! Allocation-free policy core for a future isolated Windows driver host.
//!
//! This crate models the bounded parts of the WDM I/O manager that can be
//! implemented without giving guest drivers kernel authority: driver and
//! device objects, device-stack attachment, major-function dispatch lookup,
//! IOCTL decoding, and transactional IRP lifetime state. It does not execute
//! a `.sys` image, expose physical memory, or claim KMDF/UMDF compatibility.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod abi;
mod objects;
mod request;
mod resource;

pub use abi::{
    IoAccess, IoControlCode, IoMethod, MajorFunction, IRP_MJ_MAXIMUM_FUNCTION, MAJOR_FUNCTION_COUNT,
};
pub use objects::{
    DeviceId, DeviceObject, DeviceStack, DriverId, DriverObject, DriverRegistry, RegistryError,
    MAX_DEVICE_OBJECTS, MAX_DEVICE_STACK_DEPTH, MAX_DRIVER_OBJECTS,
};
pub use request::{
    Completion, IoRequest, RequestError, RequestId, RequestPool, RequestState,
    MAX_IO_TRANSFER_BYTES, MAX_REQUESTS,
};
pub use resource::{
    HardwareGrant, HardwareGrantTable, HardwareResource, ResourceError, ResourceId, ResourceRights,
    MAX_DMA_TRANSFER_BYTES, MAX_HARDWARE_GRANTS, MAX_MMIO_GRANT_BYTES,
};

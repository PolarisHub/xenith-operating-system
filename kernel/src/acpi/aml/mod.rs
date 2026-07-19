//! Bounded ACPI Machine Language parser and evaluator.
//!
//! The loader builds a canonical namespace from DSDT AML, retaining methods,
//! devices, operation regions, and fields. Evaluation has explicit recursion,
//! loop, namespace, package, buffer, and instruction limits. Hardware region
//! access is routed through [`RegionHandler`] and denied by default.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::sync::SpinLock;

mod eval;
mod namespace;
mod parser;
mod region;
mod resource;
mod value;

use eval::Evaluator;
pub use namespace::{normalize_path, Namespace, NamespaceObject};
use parser::Loader;
use region::deny_handler;
pub use region::{DenyRegionHandler, RegionHandler, RegionSpace};
pub use resource::{decode_prt, decode_resources};
pub use value::{AmlValue, DeviceStatus, PciRoute, Resource};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmlError {
    NoDsdt,
    AlreadyInitialized,
    UnexpectedEof(usize),
    InvalidPackageLength(usize),
    InvalidName,
    InvalidString(usize),
    DuplicateName(String),
    NotFound(String),
    UnresolvedExternal(String),
    UnsupportedOpcode(u8, usize),
    UnsupportedExtendedOpcode(u8, usize),
    TypeMismatch(&'static str),
    ArgumentCount,
    InvalidTarget,
    IndexOutOfBounds,
    DivideByZero,
    InvalidRegion,
    InvalidField,
    RegionAccessDenied,
    RecursionLimit,
    ExecutionLimit,
    LoopLimit,
    UnexpectedBreak,
    LimitExceeded(&'static str),
    MalformedResource,
    InvalidRoute,
}

impl fmt::Display for AmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDsdt => f.write_str("DSDT is unavailable"),
            Self::AlreadyInitialized => f.write_str("AML namespace is already initialized"),
            Self::UnexpectedEof(offset) => write!(f, "unexpected AML end at byte {offset}"),
            Self::InvalidPackageLength(offset) => {
                write!(f, "invalid AML package length at byte {offset}")
            },
            Self::InvalidName => f.write_str("invalid AML name string"),
            Self::InvalidString(offset) => write!(f, "invalid AML string at byte {offset}"),
            Self::DuplicateName(name) => write!(f, "duplicate AML object {name}"),
            Self::NotFound(name) => write!(f, "AML object {name} was not found"),
            Self::UnresolvedExternal(name) => write!(f, "AML external {name} is unresolved"),
            Self::UnsupportedOpcode(opcode, offset) => {
                write!(f, "unsupported AML opcode 0x{opcode:02x} at byte {offset}")
            },
            Self::UnsupportedExtendedOpcode(opcode, offset) => write!(
                f,
                "unsupported AML extended opcode 0x5b{opcode:02x} at byte {offset}"
            ),
            Self::TypeMismatch(expected) => write!(f, "AML value is not {expected}"),
            Self::ArgumentCount => f.write_str("AML method argument count mismatch"),
            Self::InvalidTarget => f.write_str("invalid AML store target"),
            Self::IndexOutOfBounds => f.write_str("AML index is out of bounds"),
            Self::DivideByZero => f.write_str("AML division by zero"),
            Self::InvalidRegion => f.write_str("invalid AML operation region"),
            Self::InvalidField => f.write_str("invalid AML field unit"),
            Self::RegionAccessDenied => f.write_str("AML operation-region access denied"),
            Self::RecursionLimit => f.write_str("AML method recursion limit exceeded"),
            Self::ExecutionLimit => f.write_str("AML instruction budget exceeded"),
            Self::LoopLimit => f.write_str("AML loop iteration budget exceeded"),
            Self::UnexpectedBreak => f.write_str("AML Break escaped a loop"),
            Self::LimitExceeded(limit) => write!(f, "AML {limit} limit exceeded"),
            Self::MalformedResource => f.write_str("malformed ACPI resource template"),
            Self::InvalidRoute => f.write_str("malformed PCI routing package"),
        }
    }
}

/// Parsed AML namespace plus its policy-bearing operation-region backend.
pub struct AmlContext {
    namespace: Namespace,
    region_handler: Arc<dyn RegionHandler>,
}

impl AmlContext {
    pub fn load(table: &[u8]) -> Result<Self, AmlError> {
        Self::load_with_handler(table, deny_handler())
    }

    pub fn load_blocks<'a>(blocks: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, AmlError> {
        Self::load_blocks_with_handler(blocks, deny_handler())
    }

    pub fn load_with_handler(
        table: &[u8],
        region_handler: Arc<dyn RegionHandler>,
    ) -> Result<Self, AmlError> {
        Ok(Self {
            namespace: Loader::load(table)?,
            region_handler,
        })
    }

    pub fn load_blocks_with_handler<'a>(
        blocks: impl IntoIterator<Item = &'a [u8]>,
        region_handler: Arc<dyn RegionHandler>,
    ) -> Result<Self, AmlError> {
        Ok(Self {
            namespace: Loader::load_blocks(blocks)?,
            region_handler,
        })
    }

    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    pub fn set_region_handler(&mut self, handler: Arc<dyn RegionHandler>) {
        self.region_handler = handler;
    }

    pub fn evaluate(&mut self, path: &str, args: &[AmlValue]) -> Result<AmlValue, AmlError> {
        let path = normalize_path(path)?;
        Evaluator::new(&mut self.namespace, self.region_handler.as_ref()).evaluate(&path, args)
    }

    pub fn device_status(&mut self, device_path: &str) -> Result<DeviceStatus, AmlError> {
        let device = normalize_path(device_path)?;
        let method = child_path(&device, "_STA");
        match Evaluator::new(&mut self.namespace, self.region_handler.as_ref())
            .evaluate(&method, &[])
        {
            Ok(value) => value
                .as_integer()
                .map(DeviceStatus::from_raw)
                .ok_or(AmlError::TypeMismatch("_STA integer")),
            Err(AmlError::NotFound(_)) => Ok(DeviceStatus::DEFAULT),
            Err(error) => Err(error),
        }
    }

    pub fn current_resources(&mut self, device_path: &str) -> Result<Vec<Resource>, AmlError> {
        let device = normalize_path(device_path)?;
        let method = child_path(&device, "_CRS");
        let value = Evaluator::new(&mut self.namespace, self.region_handler.as_ref())
            .evaluate(&method, &[])?;
        let AmlValue::Buffer(bytes) = value else {
            return Err(AmlError::TypeMismatch("_CRS buffer"));
        };
        decode_resources(&bytes)
    }

    pub fn pci_routes(&mut self, bridge_path: &str) -> Result<Vec<PciRoute>, AmlError> {
        let bridge = normalize_path(bridge_path)?;
        let method = child_path(&bridge, "_PRT");
        let value = Evaluator::new(&mut self.namespace, self.region_handler.as_ref())
            .evaluate(&method, &[])?;
        decode_prt(value)
    }

    /// Return every namespace object that owns a PCI `_PRT` routing table.
    ///
    /// Paths are collected before evaluation so callers can resolve bridge
    /// bus numbers against the enumerated PCI topology without holding a
    /// borrow into the AML namespace.
    pub fn pci_route_table_paths(&self) -> Vec<String> {
        self.namespace
            .paths()
            .filter_map(route_table_parent)
            .map(String::from)
            .collect()
    }
}

fn route_table_parent(path: &str) -> Option<&str> {
    path.strip_suffix("._PRT")
        .or_else(|| (path == "\\_PRT").then_some("\\"))
}

fn child_path(parent: &str, segment: &str) -> String {
    if parent == "\\" {
        alloc::format!("\\{segment}")
    } else {
        alloc::format!("{parent}.{segment}")
    }
}

static AML_CONTEXT: SpinLock<Option<AmlContext>> = SpinLock::new(None);

/// Parse the validated DSDT and all retained SSDTs into one namespace.
pub fn init_from_dsdt() -> Result<usize, AmlError> {
    let bytes = super::dsdt::aml_bytes().ok_or(AmlError::NoDsdt)?;
    let mut blocks =
        Vec::with_capacity(1 + super::tables().map_or(0, |tables| tables.ssdt_count()));
    blocks.push(bytes);
    if let Some(tables) = super::tables() {
        blocks.extend(tables.ssdt_aml_blocks());
    }
    let context = AmlContext::load_blocks(blocks.iter().copied())?;
    let objects = context.namespace().len();
    let mut global = AML_CONTEXT.lock();
    if global.is_some() {
        return Err(AmlError::AlreadyInitialized);
    }
    *global = Some(context);
    Ok(objects)
}

pub fn initialized() -> bool {
    AML_CONTEXT.lock().is_some()
}

pub fn install_region_handler(handler: Arc<dyn RegionHandler>) -> Result<(), AmlError> {
    let mut global = AML_CONTEXT.lock();
    let context = global.as_mut().ok_or(AmlError::NoDsdt)?;
    context.set_region_handler(handler);
    Ok(())
}

pub fn evaluate(path: &str, args: &[AmlValue]) -> Result<AmlValue, AmlError> {
    AML_CONTEXT
        .lock()
        .as_mut()
        .ok_or(AmlError::NoDsdt)?
        .evaluate(path, args)
}

pub fn device_status(path: &str) -> Result<DeviceStatus, AmlError> {
    AML_CONTEXT
        .lock()
        .as_mut()
        .ok_or(AmlError::NoDsdt)?
        .device_status(path)
}

pub fn current_resources(path: &str) -> Result<Vec<Resource>, AmlError> {
    AML_CONTEXT
        .lock()
        .as_mut()
        .ok_or(AmlError::NoDsdt)?
        .current_resources(path)
}

pub fn pci_routes(path: &str) -> Result<Vec<PciRoute>, AmlError> {
    AML_CONTEXT
        .lock()
        .as_mut()
        .ok_or(AmlError::NoDsdt)?
        .pci_routes(path)
}

pub fn pci_route_table_paths() -> Result<Vec<String>, AmlError> {
    Ok(AML_CONTEXT
        .lock()
        .as_ref()
        .ok_or(AmlError::NoDsdt)?
        .pci_route_table_paths())
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::namespace::{FieldUnit, OperationRegion, OperationRegionBounds, RegionTerm};
    use super::*;

    struct CountingHandler {
        bytes: [u8; 16],
        reads: [AtomicUsize; 16],
    }

    impl CountingHandler {
        fn new(bytes: [u8; 16]) -> Self {
            Self {
                bytes,
                reads: core::array::from_fn(|_| AtomicUsize::new(0)),
            }
        }

        fn reads(&self, address: usize) -> usize {
            self.reads[address].load(Ordering::Relaxed)
        }
    }

    impl RegionHandler for CountingHandler {
        fn read(&self, space: RegionSpace, address: u64, width: u8) -> Result<u64, AmlError> {
            if space != RegionSpace::SystemMemory || width != 8 {
                return Err(AmlError::InvalidRegion);
            }
            let index = usize::try_from(address).map_err(|_| AmlError::InvalidRegion)?;
            let byte = self.bytes.get(index).ok_or(AmlError::InvalidRegion)?;
            self.reads[index].fetch_add(1, Ordering::Relaxed);
            Ok(u64::from(*byte))
        }

        fn write(&self, _: RegionSpace, _: u64, _: u8, _: u64) -> Result<(), AmlError> {
            Err(AmlError::RegionAccessDenied)
        }
    }

    fn field_backed_region_aml() -> Vec<u8> {
        vec![
            // OperationRegion (BASE, SystemMemory, 0, 16)
            0x5b, 0x80, b'B', b'A', b'S', b'E', 0x00, 0x00, 0x0a, 0x10,
            // Field (BASE, ByteAcc, NoLock, Preserve) { OFFS, 8 }
            0x5b, 0x81, 0x0b, b'B', b'A', b'S', b'E', 0x00, b'O', b'F', b'F', b'S', 0x08,
            // OperationRegion (DATA, SystemMemory, Add (OFFS, 1), 1)
            0x5b, 0x80, b'D', b'A', b'T', b'A', 0x00, 0x72, b'O', b'F', b'F', b'S', 0x01, 0x00,
            0x01, // Field (DATA, ByteAcc, NoLock, Preserve) { BYTE, 8 }
            0x5b, 0x81, 0x0b, b'D', b'A', b'T', b'A', 0x00, b'B', b'Y', b'T', b'E', 0x08,
        ]
    }

    #[test]
    fn absent_sta_uses_acpi_default() {
        let aml = [0x5b, 0x82, 0x05, b'D', b'E', b'V', b'0'];
        let mut context = AmlContext::load(&aml).unwrap();
        assert_eq!(
            context.device_status("\\DEV0").unwrap(),
            DeviceStatus::DEFAULT
        );
    }

    #[test]
    fn route_table_parent_accepts_only_exact_prt_children() {
        assert_eq!(route_table_parent("\\_SB_.PCI0._PRT"), Some("\\_SB_.PCI0"));
        assert_eq!(route_table_parent("\\_PRT"), Some("\\"));
        assert_eq!(route_table_parent("\\_SB_.PCI0.XPRT"), None);
    }

    #[test]
    fn field_backed_region_is_evaluated_once_and_cached() {
        let mut bytes = [0u8; 16];
        bytes[0] = 5;
        bytes[6] = 0xab;
        let handler = Arc::new(CountingHandler::new(bytes));
        let mut context =
            AmlContext::load_with_handler(&field_backed_region_aml(), handler.clone()).unwrap();

        assert_eq!(
            context.evaluate("\\BYTE", &[]).unwrap(),
            AmlValue::Integer(0xab)
        );
        assert_eq!(
            context.evaluate("\\BYTE", &[]).unwrap(),
            AmlValue::Integer(0xab)
        );
        assert_eq!(handler.reads(0), 1, "OFFS must be resolved only once");
        assert_eq!(handler.reads(6), 2, "BYTE is read once per evaluation");
        let Some(NamespaceObject::OperationRegion(region)) = context.namespace().get("\\DATA")
        else {
            panic!("DATA region disappeared");
        };
        assert_eq!(region.bounds, OperationRegionBounds::Resolved {
            offset: 6,
            length: 1
        });
    }

    #[test]
    fn denied_region_resolution_is_not_cached() {
        let mut context = AmlContext::load(&field_backed_region_aml()).unwrap();
        assert!(matches!(
            context.evaluate("\\BYTE", &[]),
            Err(AmlError::RegionAccessDenied)
        ));
        let Some(NamespaceObject::OperationRegion(region)) = context.namespace().get("\\DATA")
        else {
            panic!("DATA region disappeared");
        };
        assert!(matches!(
            region.bounds,
            OperationRegionBounds::Deferred { .. }
        ));

        let mut bytes = [0u8; 16];
        bytes[0] = 5;
        bytes[6] = 0x5a;
        context.set_region_handler(Arc::new(CountingHandler::new(bytes)));
        assert_eq!(
            context.evaluate("\\BYTE", &[]).unwrap(),
            AmlValue::Integer(0x5a)
        );
    }

    #[test]
    fn operation_region_alias_is_resolved_before_access() {
        let mut namespace = Namespace::default();
        namespace
            .insert(
                "\\REG0".into(),
                NamespaceObject::OperationRegion(OperationRegion {
                    space: RegionSpace::SystemMemory,
                    bounds: OperationRegionBounds::Resolved {
                        offset: 3,
                        length: 1,
                    },
                }),
            )
            .unwrap();
        namespace
            .insert("\\ALIA".into(), NamespaceObject::Alias("\\REG0".into()))
            .unwrap();
        namespace
            .insert(
                "\\BYTE".into(),
                NamespaceObject::Field(FieldUnit {
                    region: "\\ALIA".into(),
                    bit_offset: 0,
                    bit_length: 8,
                    flags: 0,
                }),
            )
            .unwrap();
        let mut bytes = [0u8; 16];
        bytes[3] = 0xc3;
        let handler = Arc::new(CountingHandler::new(bytes));
        let mut context = AmlContext {
            namespace,
            region_handler: handler,
        };
        assert_eq!(
            context.evaluate("\\BYTE", &[]).unwrap(),
            AmlValue::Integer(0xc3)
        );
    }

    #[test]
    fn operation_region_reference_cycle_is_rejected_immediately() {
        let mut namespace = Namespace::default();
        namespace
            .insert(
                "\\LOOP".into(),
                NamespaceObject::OperationRegion(OperationRegion {
                    space: RegionSpace::SystemMemory,
                    bounds: OperationRegionBounds::Deferred {
                        offset: RegionTerm::Reference("\\BYTE".into()),
                        length: RegionTerm::Integer(1),
                    },
                }),
            )
            .unwrap();
        namespace
            .insert(
                "\\BYTE".into(),
                NamespaceObject::Field(FieldUnit {
                    region: "\\LOOP".into(),
                    bit_offset: 0,
                    bit_length: 8,
                    flags: 0,
                }),
            )
            .unwrap();
        let handler = Arc::new(CountingHandler::new([0; 16]));
        let mut context = AmlContext {
            namespace,
            region_handler: handler.clone(),
        };
        assert!(matches!(
            context.evaluate("\\BYTE", &[]),
            Err(AmlError::RecursionLimit)
        ));
        assert_eq!(
            handler
                .reads
                .iter()
                .map(|reads| reads.load(Ordering::Relaxed))
                .sum::<usize>(),
            0
        );
    }

    #[test]
    fn deferred_region_span_overflow_precedes_hardware_access() {
        let mut namespace = Namespace::default();
        namespace
            .insert(
                "\\RLEN".into(),
                NamespaceObject::Value(AmlValue::Integer(2)),
            )
            .unwrap();
        namespace
            .insert(
                "\\OVER".into(),
                NamespaceObject::OperationRegion(OperationRegion {
                    space: RegionSpace::SystemMemory,
                    bounds: OperationRegionBounds::Deferred {
                        offset: RegionTerm::Integer(u64::MAX),
                        length: RegionTerm::Reference("\\RLEN".into()),
                    },
                }),
            )
            .unwrap();
        namespace
            .insert(
                "\\BYTE".into(),
                NamespaceObject::Field(FieldUnit {
                    region: "\\OVER".into(),
                    bit_offset: 0,
                    bit_length: 8,
                    flags: 0,
                }),
            )
            .unwrap();
        let handler = Arc::new(CountingHandler::new([0; 16]));
        let mut context = AmlContext {
            namespace,
            region_handler: handler.clone(),
        };
        assert!(matches!(
            context.evaluate("\\BYTE", &[]),
            Err(AmlError::InvalidRegion)
        ));
        assert_eq!(
            handler
                .reads
                .iter()
                .map(|reads| reads.load(Ordering::Relaxed))
                .sum::<usize>(),
            0
        );
    }
}

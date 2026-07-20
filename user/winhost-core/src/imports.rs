//! Fixed-capacity PE module registration and import-resolution planning.

use xenith_pe::{ImportTarget, PeError, PeImage, MAX_IMPORTS_TOTAL};

/// Maximum bytes retained for one imported module name.
pub const MAX_MODULE_NAME_BYTES: usize = xenith_pe::MAX_IMPORT_NAME_BYTES;
/// Maximum bytes retained for one exported symbol name.
pub const MAX_EXPORT_NAME_BYTES: usize = xenith_pe::MAX_IMPORT_NAME_BYTES;
/// Maximum bytes retained when reporting an unsupported forwarder.
pub const MAX_FORWARDER_NAME_BYTES: usize = xenith_pe::MAX_IMPORT_NAME_BYTES;
/// Maximum const-generic module capacity accepted by this implementation.
pub const MAX_REGISTERED_MODULES: usize = 256;
/// Maximum const-generic total export capacity accepted by one registry.
pub const MAX_REGISTERED_EXPORTS: usize = 4_096;

/// Canonical case-insensitive ASCII module name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleName {
    bytes: [u8; MAX_MODULE_NAME_BYTES],
    len: u16,
}

impl ModuleName {
    const EMPTY: Self = Self {
        bytes: [0; MAX_MODULE_NAME_BYTES],
        len: 0,
    };

    /// Validates and canonicalizes a module basename.
    ///
    /// The accepted clean-room bootstrap grammar is ASCII alphanumeric plus
    /// `.`, `_`, and `-`. No extension is inserted or removed.
    pub fn parse(value: &[u8]) -> Result<Self, ModuleError> {
        if value.is_empty() || value.len() > MAX_MODULE_NAME_BYTES {
            return Err(ModuleError::InvalidModuleName);
        }
        let mut result = Self::EMPTY;
        for (index, byte) in value.iter().copied().enumerate() {
            if !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-') {
                return Err(ModuleError::InvalidModuleName);
            }
            result.bytes[index] = byte.to_ascii_uppercase();
        }
        result.len = value.len() as u16;
        Ok(result)
    }

    /// Returns the canonical uppercase ASCII bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Returns whether the module name is an API-set contract.
    #[must_use]
    pub fn is_api_set(&self) -> bool {
        self.as_bytes().starts_with(b"API-MS-WIN-") || self.as_bytes().starts_with(b"EXT-MS-WIN-")
    }
}

/// Case-sensitive printable ASCII export name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolName {
    bytes: [u8; MAX_EXPORT_NAME_BYTES],
    len: u16,
}

impl SymbolName {
    const EMPTY: Self = Self {
        bytes: [0; MAX_EXPORT_NAME_BYTES],
        len: 0,
    };

    /// Validates and copies one export name.
    pub fn parse(value: &[u8]) -> Result<Self, ModuleError> {
        if value.is_empty() || value.len() > MAX_EXPORT_NAME_BYTES {
            return Err(ModuleError::InvalidSymbolName);
        }
        let mut result = Self::EMPTY;
        for (index, byte) in value.iter().copied().enumerate() {
            if !(0x20..=0x7e).contains(&byte) {
                return Err(ModuleError::InvalidSymbolName);
            }
            result.bytes[index] = byte;
        }
        result.len = value.len() as u16;
        Ok(result)
    }

    /// Returns the exact case-sensitive export bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Validated printable ASCII forwarder string retained for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwarderName {
    bytes: [u8; MAX_FORWARDER_NAME_BYTES],
    len: u16,
}

impl ForwarderName {
    const EMPTY: Self = Self {
        bytes: [0; MAX_FORWARDER_NAME_BYTES],
        len: 0,
    };

    fn parse(value: &[u8]) -> Result<Self, ModuleError> {
        if value.is_empty() || value.len() > MAX_FORWARDER_NAME_BYTES {
            return Err(ModuleError::InvalidForwarder);
        }
        let mut dot = None;
        let mut result = Self::EMPTY;
        for (index, byte) in value.iter().copied().enumerate() {
            if !(0x21..=0x7e).contains(&byte) {
                return Err(ModuleError::InvalidForwarder);
            }
            if byte == b'.' {
                dot = Some(index);
            }
            result.bytes[index] = byte;
        }
        if matches!(dot, None | Some(0)) || dot == Some(value.len() - 1) {
            return Err(ModuleError::InvalidForwarder);
        }
        result.len = value.len() as u16;
        Ok(result)
    }

    /// Returns the original forwarder bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Stable identifier for a registered module slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ModuleId {
    slot: u16,
    generation: u16,
}

impl ModuleId {
    const INVALID: Self = Self {
        slot: 0,
        generation: 0,
    };

    /// Returns the deterministic zero-based registry slot.
    #[must_use]
    pub const fn slot(self) -> u16 {
        self.slot
    }

    /// Returns the nonzero slot generation.
    #[must_use]
    pub const fn generation(self) -> u16 {
        self.generation
    }
}

/// Export lookup key supplied by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportQuery<'a> {
    /// Exact case-sensitive ASCII symbol name.
    Name(&'a [u8]),
    /// Nonzero export ordinal.
    Ordinal(u16),
}

/// Target supplied when registering an export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportTargetRegistration<'a> {
    /// RVA within the registered module image.
    ImageRva(u32),
    /// Printable `module.symbol` or `module.#ordinal` forwarder text.
    Forwarder(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredSelector {
    Empty,
    Name(SymbolName),
    Ordinal(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredTarget {
    Empty,
    Address(u64),
    Forwarder(ForwarderName),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExportEntry {
    occupied: bool,
    module: ModuleId,
    selector: StoredSelector,
    target: StoredTarget,
}

impl ExportEntry {
    const EMPTY: Self = Self {
        occupied: false,
        module: ModuleId::INVALID,
        selector: StoredSelector::Empty,
        target: StoredTarget::Empty,
    };
}

#[derive(Clone, Copy)]
struct ModuleSlot {
    occupied: bool,
    retired: bool,
    generation: u16,
    name: ModuleName,
    image_base: u64,
    image_size: u32,
}

impl ModuleSlot {
    const EMPTY: Self = Self {
        occupied: false,
        retired: false,
        generation: 1,
        name: ModuleName::EMPTY,
        image_base: 0,
        image_size: 0,
    };
}

/// Registry mutation or name-validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleError {
    /// A const-generic capacity is zero or exceeds its documented maximum.
    InvalidCapacity {
        /// Supplied module capacity.
        modules: usize,
        /// Supplied total export capacity.
        exports: usize,
    },
    /// A module basename was empty, too long, or outside the bootstrap grammar.
    InvalidModuleName,
    /// An export name was empty, too long, or non-printable.
    InvalidSymbolName,
    /// A zero ordinal was supplied.
    InvalidOrdinal,
    /// A forwarder was malformed or beyond the retained bound.
    InvalidForwarder,
    /// A module image range was empty or overflowed.
    InvalidImageRange,
    /// A module image overlaps an existing registered module.
    OverlappingImage,
    /// The canonical module name is already registered.
    DuplicateModule,
    /// No reusable module slot remains.
    ModuleTableFull,
    /// A stale or unknown module identifier was supplied.
    InvalidModuleId,
    /// The RVA is outside the registered module image.
    ExportOutsideImage,
    /// The export key already exists in this module.
    DuplicateExport,
    /// No export slot remains in the registry.
    ExportTableFull,
}

/// Explicit outcome of an import lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportResolution {
    /// The import resolves directly to a registered guest address.
    Resolved {
        /// Module containing the export.
        module: ModuleId,
        /// Guest virtual address to write to the IAT later.
        address: u64,
    },
    /// The import module name is outside the bootstrap grammar.
    InvalidModuleName,
    /// The import symbol or ordinal is outside the bootstrap grammar.
    InvalidSymbol,
    /// The API-set contract requires a future explicit schema resolver.
    UnsupportedApiSet,
    /// No registered module has this exact case-insensitive basename.
    ModuleNotFound,
    /// The module exists but has no exact matching export.
    SymbolNotFound {
        /// Module that was searched.
        module: ModuleId,
    },
    /// The matching export is a forwarder; recursive resolution is not guessed.
    UnsupportedForwarder {
        /// Module containing the forwarder.
        module: ModuleId,
        /// Retained forwarder string for a future explicit resolver.
        forwarder: ForwarderName,
    },
}

/// Fixed-capacity module registry with one shared fixed export arena.
///
/// `M` is the module-slot count and `E` is the total export-slot count. Sharing
/// one arena avoids multiplying worst-case export storage by every module slot.
pub struct ModuleRegistry<const M: usize, const E: usize> {
    modules: [ModuleSlot; M],
    exports: [ExportEntry; E],
    len: usize,
    export_count: usize,
}

impl<const M: usize, const E: usize> ModuleRegistry<M, E> {
    /// Creates an empty registry after validating both capacities.
    pub const fn try_new() -> Result<Self, ModuleError> {
        if M == 0 || M > MAX_REGISTERED_MODULES || E == 0 || E > MAX_REGISTERED_EXPORTS {
            return Err(ModuleError::InvalidCapacity {
                modules: M,
                exports: E,
            });
        }
        Ok(Self {
            modules: [ModuleSlot::EMPTY; M],
            exports: [ExportEntry::EMPTY; E],
            len: 0,
            export_count: 0,
        })
    }

    /// Returns the number of live registered modules.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the total number of registered exports across all modules.
    #[must_use]
    pub const fn export_count(&self) -> usize {
        self.export_count
    }

    /// Registers a module in the lowest reusable slot.
    pub fn register_module(
        &mut self,
        name: &[u8],
        image_base: u64,
        image_size: u32,
    ) -> Result<ModuleId, ModuleError> {
        let name = ModuleName::parse(name)?;
        let image_end = image_base
            .checked_add(u64::from(image_size))
            .filter(|_| image_size != 0)
            .ok_or(ModuleError::InvalidImageRange)?;

        for slot in self.modules.iter().filter(|slot| slot.occupied) {
            if slot.name == name {
                return Err(ModuleError::DuplicateModule);
            }
            let slot_end = slot.image_base + u64::from(slot.image_size);
            if image_base < slot_end && slot.image_base < image_end {
                return Err(ModuleError::OverlappingImage);
            }
        }

        for (index, slot) in self.modules.iter_mut().enumerate() {
            if !slot.occupied && !slot.retired {
                slot.occupied = true;
                slot.name = name;
                slot.image_base = image_base;
                slot.image_size = image_size;
                self.len += 1;
                return Ok(ModuleId {
                    slot: index as u16,
                    generation: slot.generation,
                });
            }
        }
        Err(ModuleError::ModuleTableFull)
    }

    /// Unregisters a module and returns its image range.
    pub fn unregister_module(&mut self, id: ModuleId) -> Result<(u64, u32), ModuleError> {
        let index = self.module_index(id)?;
        let slot = &mut self.modules[index];
        let range = (slot.image_base, slot.image_size);
        slot.occupied = false;
        slot.name = ModuleName::EMPTY;
        slot.image_base = 0;
        slot.image_size = 0;
        if slot.generation == u16::MAX {
            slot.retired = true;
        } else {
            slot.generation += 1;
        }
        for export in &mut self.exports {
            if export.occupied && export.module == id {
                *export = ExportEntry::EMPTY;
                self.export_count -= 1;
            }
        }
        self.len -= 1;
        Ok(range)
    }

    /// Registers one direct address or explicitly unsupported forwarder.
    pub fn register_export(
        &mut self,
        module: ModuleId,
        query: ExportQuery<'_>,
        target: ExportTargetRegistration<'_>,
    ) -> Result<(), ModuleError> {
        let selector = stored_selector(query)?;
        let module_index = self.module_index(module)?;
        if self
            .exports
            .iter()
            .any(|entry| entry.occupied && entry.module == module && entry.selector == selector)
        {
            return Err(ModuleError::DuplicateExport);
        }
        if self.export_count == E {
            return Err(ModuleError::ExportTableFull);
        }
        let module_slot = self.modules[module_index];
        let target = match target {
            ExportTargetRegistration::ImageRva(rva) => {
                if rva >= module_slot.image_size {
                    return Err(ModuleError::ExportOutsideImage);
                }
                let address = module_slot
                    .image_base
                    .checked_add(u64::from(rva))
                    .ok_or(ModuleError::ExportOutsideImage)?;
                StoredTarget::Address(address)
            },
            ExportTargetRegistration::Forwarder(value) => {
                StoredTarget::Forwarder(ForwarderName::parse(value)?)
            },
        };
        let export = self
            .exports
            .iter_mut()
            .find(|entry| !entry.occupied)
            .ok_or(ModuleError::ExportTableFull)?;
        *export = ExportEntry {
            occupied: true,
            module,
            selector,
            target,
        };
        self.export_count += 1;
        Ok(())
    }

    /// Resolves one module and export without API-set or forwarder guessing.
    #[must_use]
    pub fn resolve(&self, module: &[u8], query: ExportQuery<'_>) -> ImportResolution {
        let Ok(module_name) = ModuleName::parse(module) else {
            return ImportResolution::InvalidModuleName;
        };
        let Ok(selector) = stored_selector(query) else {
            return ImportResolution::InvalidSymbol;
        };
        self.resolve_stored(module_name, selector)
    }

    /// Builds a complete, allocation-free import plan from a validated PE image.
    ///
    /// This never writes an IAT. All imported records are validated by
    /// `xenith-pe` before a plan is returned.
    pub fn plan_imports<const N: usize>(
        &self,
        image: &PeImage<'_>,
    ) -> Result<ImportResolutionPlan<N>, ImportPlanError> {
        if N > MAX_IMPORTS_TOTAL {
            return Err(ImportPlanError::InvalidCapacity {
                capacity: N,
                maximum: MAX_IMPORTS_TOTAL,
            });
        }
        let summary = image.import_summary().map_err(ImportPlanError::Pe)?;
        if summary.import_count > N {
            return Err(ImportPlanError::PlanFull {
                required: summary.import_count,
                capacity: N,
            });
        }

        let mut plan = ImportResolutionPlan {
            bindings: [ImportBinding::EMPTY; N],
            len: 0,
            unresolved: 0,
        };
        let mut conversion_error = None;
        image
            .visit_imports(|record| {
                if conversion_error.is_some() {
                    return;
                }
                let module_name = match ModuleName::parse(record.module_name) {
                    Ok(value) => value,
                    Err(_) => {
                        conversion_error = Some(ImportPlanError::InvalidModuleName {
                            descriptor_index: record.descriptor_index,
                        });
                        return;
                    },
                };
                let (symbol, selector) = match record.target {
                    ImportTarget::Ordinal(ordinal) => (
                        ImportSymbol::Ordinal(ordinal),
                        StoredSelector::Ordinal(ordinal),
                    ),
                    ImportTarget::Name { hint, name } => {
                        let name = match SymbolName::parse(name) {
                            Ok(value) => value,
                            Err(_) => {
                                conversion_error = Some(ImportPlanError::InvalidSymbolName {
                                    descriptor_index: record.descriptor_index,
                                    thunk_index: record.thunk_index,
                                });
                                return;
                            },
                        };
                        (
                            ImportSymbol::Name { hint, name },
                            StoredSelector::Name(name),
                        )
                    },
                };
                let resolution = self.resolve_stored(module_name, selector);
                if !matches!(resolution, ImportResolution::Resolved { .. }) {
                    plan.unresolved += 1;
                }
                plan.bindings[plan.len] = ImportBinding {
                    descriptor_index: record.descriptor_index,
                    thunk_index: record.thunk_index,
                    lookup_rva: record.lookup_rva,
                    iat_rva: record.iat_rva,
                    module: module_name,
                    symbol,
                    resolution,
                };
                plan.len += 1;
            })
            .map_err(ImportPlanError::Pe)?;
        if let Some(error) = conversion_error {
            return Err(error);
        }
        Ok(plan)
    }

    fn resolve_stored(
        &self,
        module_name: ModuleName,
        selector: StoredSelector,
    ) -> ImportResolution {
        if module_name.is_api_set() {
            return ImportResolution::UnsupportedApiSet;
        }
        let Some((index, slot)) = self
            .modules
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.occupied && slot.name == module_name)
        else {
            return ImportResolution::ModuleNotFound;
        };
        let id = ModuleId {
            slot: index as u16,
            generation: slot.generation,
        };
        let Some(export) = self
            .exports
            .iter()
            .find(|entry| entry.occupied && entry.module == id && entry.selector == selector)
        else {
            return ImportResolution::SymbolNotFound { module: id };
        };
        match export.target {
            StoredTarget::Address(address) => ImportResolution::Resolved {
                module: id,
                address,
            },
            StoredTarget::Forwarder(forwarder) => ImportResolution::UnsupportedForwarder {
                module: id,
                forwarder,
            },
            StoredTarget::Empty => ImportResolution::SymbolNotFound { module: id },
        }
    }

    fn module_index(&self, id: ModuleId) -> Result<usize, ModuleError> {
        let index = usize::from(id.slot);
        let slot = self
            .modules
            .get(index)
            .ok_or(ModuleError::InvalidModuleId)?;
        if !slot.occupied || slot.retired || slot.generation != id.generation {
            return Err(ModuleError::InvalidModuleId);
        }
        Ok(index)
    }
}

fn stored_selector(query: ExportQuery<'_>) -> Result<StoredSelector, ModuleError> {
    match query {
        ExportQuery::Name(name) => Ok(StoredSelector::Name(SymbolName::parse(name)?)),
        ExportQuery::Ordinal(0) => Err(ModuleError::InvalidOrdinal),
        ExportQuery::Ordinal(ordinal) => Ok(StoredSelector::Ordinal(ordinal)),
    }
}

/// Owned imported symbol retained in a planner entry.
// Inline fixed storage is intentional: production code cannot allocate or box
// the named variant, and each plan entry must own its bounded source name.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportSymbol {
    /// Import by nonzero ordinal.
    Ordinal(u16),
    /// Import by exact case-sensitive name.
    Name {
        /// Linker-supplied export hint.
        hint: u16,
        /// Imported symbol name.
        name: SymbolName,
    },
}

/// One declarative IAT-binding decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportBinding {
    /// Import descriptor index.
    pub descriptor_index: usize,
    /// Thunk index within the descriptor.
    pub thunk_index: usize,
    /// Lookup-table RVA read by the PE parser.
    pub lookup_rva: u32,
    /// IAT RVA a later loader may patch after checking the outcome.
    pub iat_rva: u32,
    /// Canonical requested module name.
    pub module: ModuleName,
    /// Owned imported symbol.
    pub symbol: ImportSymbol,
    /// Explicit lookup result.
    pub resolution: ImportResolution,
}

impl ImportBinding {
    const EMPTY: Self = Self {
        descriptor_index: 0,
        thunk_index: 0,
        lookup_rva: 0,
        iat_rva: 0,
        module: ModuleName::EMPTY,
        symbol: ImportSymbol::Ordinal(0),
        resolution: ImportResolution::ModuleNotFound,
    };
}

/// Complete fixed-capacity import-resolution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportResolutionPlan<const N: usize> {
    bindings: [ImportBinding; N],
    len: usize,
    unresolved: usize,
}

impl<const N: usize> ImportResolutionPlan<N> {
    /// Returns bindings in original PE descriptor/thunk order.
    #[must_use]
    pub fn bindings(&self) -> &[ImportBinding] {
        &self.bindings[..self.len]
    }

    /// Returns the number of imports in this plan.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the PE has no regular imports.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of entries that are not direct addresses.
    #[must_use]
    pub const fn unresolved_count(&self) -> usize {
        self.unresolved
    }

    /// Returns whether every import resolved directly.
    #[must_use]
    pub const fn is_fully_resolved(&self) -> bool {
        self.unresolved == 0
    }
}

/// Import-plan construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportPlanError {
    /// Plan capacity exceeds the parser's global import bound.
    InvalidCapacity {
        /// Supplied const-generic capacity.
        capacity: usize,
        /// Largest accepted capacity.
        maximum: usize,
    },
    /// The validated image has more imports than this plan can retain.
    PlanFull {
        /// Number of imports in the image.
        required: usize,
        /// Number of available plan entries.
        capacity: usize,
    },
    /// `xenith-pe` rejected the image or its import graph.
    Pe(PeError),
    /// A parser-valid printable module name is outside this bootstrap grammar.
    InvalidModuleName {
        /// Descriptor containing the name.
        descriptor_index: usize,
    },
    /// An imported name could not be retained by this planner.
    InvalidSymbolName {
        /// Descriptor containing the thunk.
        descriptor_index: usize,
        /// Thunk containing the name.
        thunk_index: usize,
    },
}

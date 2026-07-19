//! Safe ownership and executable probes for Windows Hypervisor Platform partitions.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhpError {
    Unavailable,
    CreatePartition(i32),
    SetProcessorCount(i32),
    SetLocalApicMode(i32),
    SetupPartition(i32),
    CreateProcessor { index: u32, result: i32 },
    AllocateGuestMemory,
    MapGuestMemory(i32),
    SetRegisters(i32),
    RunProcessor(i32),
    InvalidIoExit,
    UnexpectedExit(u32),
    UnexpectedMachineExit {
        reason: u32,
        rip: u64,
        rflags: u64,
        rsp: u64,
        cr2: u64,
        cr3: u64,
        gs_base: u64,
        kernel_gs_base: u64,
    },
    GuestException {
        vector: u8,
        error_code: u32,
        parameter: u64,
        rip: u64,
        instruction_bytes: [u8; 16],
        instruction_len: u8,
    },
    ExecutionLimit,
    GetRegisters(i32),
    CreateInstructionEmulator(i32),
    InstructionEmulation { result: i32, status: u32 },
    GuestMemoryAccess,
    CancelProcessor(i32),
}

impl fmt::Display for WhpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for WhpError {}

/// Evidence returned after WHP executes guest instructions and the host handles
/// the resulting I/O and halt exits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WhpExecutionProof {
    pub exits: u32,
    pub port: u16,
    pub value: u8,
}

#[cfg(windows)]
mod platform {
    use core::ffi::c_void;
    use core::{mem, ptr};

    use super::{WhpError, WhpExecutionProof};

    type PartitionHandle = *mut c_void;
    const CAPABILITY_HYPERVISOR_PRESENT: u32 = 0;
    const PROPERTY_PROCESSOR_COUNT: u32 = 0x0000_1FFF;
    const PROPERTY_LOCAL_APIC_MODE: u32 = 0x0000_1005;
    const LOCAL_APIC_X2APIC: u32 = 2;
    const MAP_READ_WRITE_EXECUTE: u32 = 0x7;
    const EXIT_IO_PORT_ACCESS: u32 = 0x2;
    const EXIT_HALT: u32 = 0x8;
    const REGISTER_RIP: u32 = 0x10;
    const REGISTER_RFLAGS: u32 = 0x11;
    const REGISTER_ES: u32 = 0x12;
    const REGISTER_CS: u32 = 0x13;
    const REGISTER_SS: u32 = 0x14;
    const REGISTER_DS: u32 = 0x15;
    const REGISTER_FS: u32 = 0x16;
    const REGISTER_GS: u32 = 0x17;
    const REGISTER_CR0: u32 = 0x1C;
    const PAGE_SIZE: usize = 4096;
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct SegmentRegister {
        base: u64,
        limit: u32,
        selector: u16,
        attributes: u16,
    }

    #[repr(C, align(16))]
    #[derive(Clone, Copy, Default)]
    struct RegisterValue {
        words: [u64; 2],
    }

    impl RegisterValue {
        const fn reg64(value: u64) -> Self {
            Self { words: [value, 0] }
        }

        const fn segment(segment: SegmentRegister) -> Self {
            Self {
                words: [
                    segment.base,
                    segment.limit as u64
                        | ((segment.selector as u64) << 32)
                        | ((segment.attributes as u64) << 48),
                ],
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct VpExitContext {
        execution_state: u16,
        instruction_length_and_cr8: u8,
        reserved: u8,
        reserved2: u32,
        cs: SegmentRegister,
        rip: u64,
        rflags: u64,
    }

    impl VpExitContext {
        const fn instruction_length(self) -> u8 {
            self.instruction_length_and_cr8 & 0x0F
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct IoPortAccessContext {
        instruction_byte_count: u8,
        reserved: [u8; 3],
        instruction_bytes: [u8; 16],
        access_info: u32,
        port_number: u16,
        reserved2: [u16; 3],
        rax: u64,
        rcx: u64,
        rsi: u64,
        rdi: u64,
        ds: SegmentRegister,
        es: SegmentRegister,
    }

    #[repr(C)]
    union ExitDetails {
        io_port_access: IoPortAccessContext,
        raw: [u64; 22],
    }

    impl Default for ExitDetails {
        fn default() -> Self {
            Self { raw: [0; 22] }
        }
    }

    #[repr(C)]
    #[derive(Default)]
    struct RunVpExitContext {
        exit_reason: u32,
        reserved: u32,
        vp_context: VpExitContext,
        details: ExitDetails,
    }

    const _: () = assert!(mem::size_of::<SegmentRegister>() == 16);
    const _: () = assert!(mem::size_of::<RegisterValue>() == 16);
    const _: () = assert!(mem::size_of::<VpExitContext>() == 40);
    const _: () = assert!(mem::size_of::<IoPortAccessContext>() == 96);
    const _: () = assert!(mem::size_of::<RunVpExitContext>() == 224);

    #[link(name = "WinHvPlatform")]
    extern "system" {
        fn WHvGetCapability(
            code: u32,
            buffer: *mut c_void,
            buffer_size: u32,
            written: *mut u32,
        ) -> i32;
        fn WHvCreatePartition(partition: *mut PartitionHandle) -> i32;
        fn WHvSetPartitionProperty(
            partition: PartitionHandle,
            code: u32,
            buffer: *const c_void,
            buffer_size: u32,
        ) -> i32;
        fn WHvSetupPartition(partition: PartitionHandle) -> i32;
        fn WHvCreateVirtualProcessor(partition: PartitionHandle, index: u32, flags: u32) -> i32;
        fn WHvDeleteVirtualProcessor(partition: PartitionHandle, index: u32) -> i32;
        fn WHvDeletePartition(partition: PartitionHandle) -> i32;
        fn WHvMapGpaRange(
            partition: PartitionHandle,
            source_address: *const c_void,
            guest_address: u64,
            size_in_bytes: u64,
            flags: u32,
        ) -> i32;
        fn WHvUnmapGpaRange(
            partition: PartitionHandle,
            guest_address: u64,
            size_in_bytes: u64,
        ) -> i32;
        fn WHvSetVirtualProcessorRegisters(
            partition: PartitionHandle,
            index: u32,
            register_names: *const u32,
            register_count: u32,
            register_values: *const RegisterValue,
        ) -> i32;
        fn WHvRunVirtualProcessor(
            partition: PartitionHandle,
            index: u32,
            exit_context: *mut c_void,
            exit_context_size: u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protection: u32,
        ) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
    }

    fn succeeded(result: i32) -> bool {
        result >= 0
    }

    pub struct WhpPartition {
        handle: PartitionHandle,
        processor_count: u32,
    }

    struct GuestPage {
        partition: PartitionHandle,
        host: *mut c_void,
    }

    impl GuestPage {
        fn map(partition: PartitionHandle, bytes: &[u8]) -> Result<Self, WhpError> {
            // SAFETY: the requested allocation has explicit size and page protection.
            let host = unsafe {
                VirtualAlloc(
                    ptr::null_mut(),
                    PAGE_SIZE,
                    MEM_COMMIT_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if host.is_null() {
                return Err(WhpError::AllocateGuestMemory);
            }
            // SAFETY: `host` owns PAGE_SIZE writable bytes and `bytes` is bounded below.
            unsafe {
                ptr::write_bytes(host.cast::<u8>(), 0, PAGE_SIZE);
                ptr::copy_nonoverlapping(bytes.as_ptr(), host.cast::<u8>(), bytes.len());
            }
            // SAFETY: `host` is page-aligned VirtualAlloc memory and the partition is live.
            let result = unsafe {
                WHvMapGpaRange(partition, host, 0, PAGE_SIZE as u64, MAP_READ_WRITE_EXECUTE)
            };
            if !succeeded(result) {
                // SAFETY: `host` is an allocation returned by VirtualAlloc.
                let _ = unsafe { VirtualFree(host, 0, MEM_RELEASE) };
                return Err(WhpError::MapGuestMemory(result));
            }
            Ok(Self { partition, host })
        }
    }

    impl Drop for GuestPage {
        fn drop(&mut self) {
            // SAFETY: the exact GPA range was mapped by `GuestPage::map`.
            let _ = unsafe { WHvUnmapGpaRange(self.partition, 0, PAGE_SIZE as u64) };
            // SAFETY: `host` is the sole VirtualAlloc allocation owned by this object.
            let _ = unsafe { VirtualFree(self.host, 0, MEM_RELEASE) };
        }
    }

    impl WhpPartition {
        #[must_use]
        pub fn is_available() -> bool {
            let mut present = 0u32;
            let mut written = 0u32;
            // SAFETY: both output pointers refer to correctly sized writable values.
            let result = unsafe {
                WHvGetCapability(
                    CAPABILITY_HYPERVISOR_PRESENT,
                    ptr::from_mut(&mut present).cast(),
                    core::mem::size_of::<u32>() as u32,
                    &mut written,
                )
            };
            succeeded(result) && written >= 1 && present != 0
        }

        pub fn create(processor_count: u32) -> Result<Self, WhpError> {
            Self::create_with_apic(processor_count, false)
        }

        pub(crate) fn create_accelerated(processor_count: u32) -> Result<Self, WhpError> {
            Self::create_with_apic(processor_count, true)
        }

        fn create_with_apic(processor_count: u32, emulate_x2apic: bool) -> Result<Self, WhpError> {
            if processor_count == 0 || !Self::is_available() {
                return Err(WhpError::Unavailable);
            }
            let mut handle = ptr::null_mut();
            // SAFETY: the API initializes `handle` on success.
            let result = unsafe { WHvCreatePartition(&mut handle) };
            if !succeeded(result) {
                return Err(WhpError::CreatePartition(result));
            }
            let mut partition = Self {
                handle,
                processor_count: 0,
            };
            // SAFETY: handle is owned by `partition`; the property buffer is a valid u32.
            let result = unsafe {
                WHvSetPartitionProperty(
                    partition.handle,
                    PROPERTY_PROCESSOR_COUNT,
                    ptr::from_ref(&processor_count).cast(),
                    core::mem::size_of::<u32>() as u32,
                )
            };
            if !succeeded(result) {
                return Err(WhpError::SetProcessorCount(result));
            }
            if emulate_x2apic {
                let local_apic_mode = LOCAL_APIC_X2APIC;
                // SAFETY: this pre-setup property accepts one enum-sized u32.
                let result = unsafe {
                    WHvSetPartitionProperty(
                        partition.handle,
                        PROPERTY_LOCAL_APIC_MODE,
                        ptr::from_ref(&local_apic_mode).cast(),
                        mem::size_of::<u32>() as u32,
                    )
                };
                if !succeeded(result) {
                    return Err(WhpError::SetLocalApicMode(result));
                }

            }
            // SAFETY: all required pre-setup properties have been installed.
            let result = unsafe { WHvSetupPartition(partition.handle) };
            if !succeeded(result) {
                return Err(WhpError::SetupPartition(result));
            }
            for index in 0..processor_count {
                // SAFETY: index is within the processor count configured above.
                let result = unsafe { WHvCreateVirtualProcessor(partition.handle, index, 0) };
                if !succeeded(result) {
                    return Err(WhpError::CreateProcessor { index, result });
                }
                partition.processor_count += 1;
            }
            Ok(partition)
        }

        #[must_use]
        pub const fn processor_count(&self) -> u32 {
            self.processor_count
        }

        pub(crate) const fn raw_handle(&self) -> *mut c_void {
            self.handle
        }

        /// Execute a real-mode program through WHP, service its serial `OUT`,
        /// and require the following `HLT` exit. This proves more than API
        /// availability: guest memory, register state, vCPU execution, and
        /// exit handling all cross the host hypervisor boundary.
        pub fn run_execution_probe(&mut self) -> Result<WhpExecutionProof, WhpError> {
            const PROGRAM: &[u8] = &[0xBA, 0xF8, 0x03, 0xB0, b'X', 0xEE, 0xF4];
            const MAX_EXITS: u32 = 8;
            if self.processor_count == 0 {
                return Err(WhpError::Unavailable);
            }
            let _memory = GuestPage::map(self.handle, PROGRAM)?;
            let code = SegmentRegister {
                base: 0,
                limit: 0xFFFF,
                selector: 0,
                attributes: 0x009B,
            };
            let data = SegmentRegister {
                base: 0,
                limit: 0xFFFF,
                selector: 0,
                attributes: 0x0093,
            };
            let names = [
                REGISTER_RIP,
                REGISTER_RFLAGS,
                REGISTER_CS,
                REGISTER_SS,
                REGISTER_DS,
                REGISTER_ES,
                REGISTER_FS,
                REGISTER_GS,
                REGISTER_CR0,
            ];
            let values = [
                RegisterValue::reg64(0),
                RegisterValue::reg64(2),
                RegisterValue::segment(code),
                RegisterValue::segment(data),
                RegisterValue::segment(data),
                RegisterValue::segment(data),
                RegisterValue::segment(data),
                RegisterValue::segment(data),
                RegisterValue::reg64(0x10),
            ];
            // SAFETY: all register names and values have identical valid lengths.
            let result = unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.handle,
                    0,
                    names.as_ptr(),
                    names.len() as u32,
                    values.as_ptr(),
                )
            };
            if !succeeded(result) {
                return Err(WhpError::SetRegisters(result));
            }

            let mut proof = WhpExecutionProof {
                exits: 0,
                port: 0,
                value: 0,
            };
            while proof.exits < MAX_EXITS {
                let mut context = RunVpExitContext::default();
                // SAFETY: the output context has the exact WHP x64 ABI size.
                let result = unsafe {
                    WHvRunVirtualProcessor(
                        self.handle,
                        0,
                        ptr::from_mut(&mut context).cast(),
                        mem::size_of::<RunVpExitContext>() as u32,
                    )
                };
                if !succeeded(result) {
                    return Err(WhpError::RunProcessor(result));
                }
                proof.exits += 1;
                match context.exit_reason {
                    EXIT_IO_PORT_ACCESS => {
                        // SAFETY: WHP selected the I/O member of the tagged exit union.
                        let io = unsafe { context.details.io_port_access };
                        let is_write = io.access_info & 1 != 0;
                        let access_size = (io.access_info >> 1) & 0x7;
                        let length = context.vp_context.instruction_length();
                        if !is_write || access_size != 1 || io.port_number != 0x3F8 || length == 0 {
                            return Err(WhpError::InvalidIoExit);
                        }
                        proof.port = io.port_number;
                        proof.value = io.rax as u8;
                        let rip_name = [REGISTER_RIP];
                        let rip_value = [RegisterValue::reg64(
                            context.vp_context.rip.wrapping_add(u64::from(length)),
                        )];
                        // SAFETY: the single RIP name has one matching register value.
                        let result = unsafe {
                            WHvSetVirtualProcessorRegisters(
                                self.handle,
                                0,
                                rip_name.as_ptr(),
                                1,
                                rip_value.as_ptr(),
                            )
                        };
                        if !succeeded(result) {
                            return Err(WhpError::SetRegisters(result));
                        }
                    },
                    EXIT_HALT if proof.port == 0x3F8 && proof.value == b'X' => return Ok(proof),
                    other => return Err(WhpError::UnexpectedExit(other)),
                }
            }
            Err(WhpError::ExecutionLimit)
        }
    }

    impl Drop for WhpPartition {
        fn drop(&mut self) {
            for index in (0..self.processor_count).rev() {
                // SAFETY: each index was created successfully and remains owned by the partition.
                let _ = unsafe { WHvDeleteVirtualProcessor(self.handle, index) };
            }
            if !self.handle.is_null() {
                // SAFETY: this is the sole owning handle and all virtual processors are deleted.
                let _ = unsafe { WHvDeletePartition(self.handle) };
            }
        }
    }

    // WHP partition handles may be moved between host threads but are not concurrently accessed here.
    unsafe impl Send for WhpPartition {}
}

#[cfg(not(windows))]
mod platform {
    use super::{WhpError, WhpExecutionProof};

    pub struct WhpPartition;
    impl WhpPartition {
        #[must_use]
        pub const fn is_available() -> bool {
            false
        }
        pub fn create(_processor_count: u32) -> Result<Self, WhpError> {
            Err(WhpError::Unavailable)
        }
        pub(crate) fn create_accelerated(_processor_count: u32) -> Result<Self, WhpError> {
            Err(WhpError::Unavailable)
        }
        #[must_use]
        pub const fn processor_count(&self) -> u32 {
            0
        }
        pub fn run_execution_probe(&mut self) -> Result<WhpExecutionProof, WhpError> {
            Err(WhpError::Unavailable)
        }
    }
}

pub use platform::WhpPartition;

#[cfg(all(test, windows))]
mod tests {
    use super::WhpPartition;

    #[test]
    fn whp_executes_guest_code_and_services_exits_when_available() {
        if !WhpPartition::is_available() {
            return;
        }
        let mut partition = WhpPartition::create(1).expect("create WHP partition");
        let proof = partition
            .run_execution_probe()
            .expect("execute WHP guest probe");
        assert_eq!(proof.port, 0x3F8);
        assert_eq!(proof.value, b'X');
        assert_eq!(proof.exits, 2);
    }
}

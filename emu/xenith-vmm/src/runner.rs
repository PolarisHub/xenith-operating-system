//! WHP execution loop bridged to Xenith's shared PC device model.

use std::time::Duration;

#[cfg(not(windows))]
use xenith_emu::Machine;

use crate::{WhpError, WhpPartition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhpRunReason {
    Halted,
    ShellReady,
    TimedOut,
    ExitLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WhpRunSummary {
    pub reason: WhpRunReason,
    pub exits: u64,
}

#[cfg(windows)]
mod platform {
    use core::ffi::c_void;
    use core::{mem, ptr, slice};
    use std::sync::mpsc;
    use std::thread;

    use xenith_emu::{Machine, MemoryBus};

    use super::{Duration, WhpError, WhpPartition, WhpRunReason, WhpRunSummary};

    type PartitionHandle = *mut c_void;
    type EmulatorHandle = *mut c_void;

    const S_OK: i32 = 0;
    const E_FAIL: i32 = 0x8000_4005_u32 as i32;
    const MAP_READ_WRITE_EXECUTE: u32 = 0x7;
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_SIZE: usize = 4096;
    const DEVICE_TICK_PER_EXIT: u64 = 256;

    const EXIT_MEMORY_ACCESS: u32 = 0x1;
    const EXIT_IO_PORT_ACCESS: u32 = 0x2;
    const EXIT_HALT: u32 = 0x8;
    const EXIT_APIC_EOI: u32 = 0x9;
    const EXIT_EXCEPTION: u32 = 0x1002;
    const EXIT_CANCELED: u32 = 0x2001;

    const REGISTER_RIP: u32 = 0x10;
    const REGISTER_RFLAGS: u32 = 0x11;
    const REGISTER_ES: u32 = 0x12;
    const REGISTER_CS: u32 = 0x13;
    const REGISTER_SS: u32 = 0x14;
    const REGISTER_DS: u32 = 0x15;
    const REGISTER_FS: u32 = 0x16;
    const REGISTER_GS: u32 = 0x17;
    const REGISTER_CR0: u32 = 0x1C;
    const REGISTER_CR2: u32 = 0x1D;
    const REGISTER_CR3: u32 = 0x1E;
    const REGISTER_CR4: u32 = 0x1F;
    const REGISTER_EFER: u32 = 0x2001;
    const REGISTER_KERNEL_GS_BASE: u32 = 0x2002;

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

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct MemoryAccessContext {
        instruction_byte_count: u8,
        reserved: [u8; 3],
        instruction_bytes: [u8; 16],
        access_info: u32,
        gpa: u64,
        gva: u64,
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
    #[derive(Clone, Copy, Default)]
    struct ExceptionContext {
        instruction_byte_count: u8,
        reserved: [u8; 3],
        instruction_bytes: [u8; 16],
        exception_info: u32,
        exception_type: u8,
        reserved2: [u8; 3],
        error_code: u32,
        exception_parameter: u64,
    }

    #[repr(C)]
    union ExitDetails {
        memory_access: MemoryAccessContext,
        io_port_access: IoPortAccessContext,
        exception: ExceptionContext,
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

    #[repr(C)]
    struct EmulatorIoAccess {
        direction: u8,
        port: u16,
        access_size: u16,
        data: u32,
    }

    #[repr(C)]
    struct EmulatorMemoryAccess {
        gpa_address: u64,
        direction: u8,
        access_size: u8,
        data: [u8; 8],
    }

    type IoCallback = unsafe extern "system" fn(*mut c_void, *mut EmulatorIoAccess) -> i32;
    type MemoryCallback = unsafe extern "system" fn(*mut c_void, *mut EmulatorMemoryAccess) -> i32;
    type GetRegistersCallback =
        unsafe extern "system" fn(*mut c_void, *const u32, u32, *mut RegisterValue) -> i32;
    type SetRegistersCallback =
        unsafe extern "system" fn(*mut c_void, *const u32, u32, *const RegisterValue) -> i32;
    type TranslateCallback =
        unsafe extern "system" fn(*mut c_void, u64, u32, *mut u32, *mut u64) -> i32;

    #[repr(C)]
    struct EmulatorCallbacks {
        size: u32,
        reserved: u32,
        io: Option<IoCallback>,
        memory: Option<MemoryCallback>,
        get_registers: Option<GetRegistersCallback>,
        set_registers: Option<SetRegistersCallback>,
        translate: Option<TranslateCallback>,
    }

    #[repr(C)]
    #[derive(Default)]
    struct TranslateResult {
        code: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct InterruptControl {
        control: u64,
        destination: u32,
        vector: u32,
    }

    struct CallbackContext {
        partition: PartitionHandle,
        vp_index: u32,
        bus: *mut MemoryBus,
    }

    struct RunWatchdog {
        finished: Option<mpsc::Sender<()>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl RunWatchdog {
        fn start(partition: PartitionHandle, timeout: Duration) -> Self {
            let (finished, receiver) = mpsc::channel();
            let partition = partition as usize;
            let thread = thread::spawn(move || {
                if receiver.recv_timeout(timeout).is_err() {
                    // SAFETY: the owner joins this thread before it can drop the partition.
                    let _ =
                        unsafe { WHvCancelRunVirtualProcessor(partition as PartitionHandle, 0, 0) };
                }
            });
            Self {
                finished: Some(finished),
                thread: Some(thread),
            }
        }
    }

    impl Drop for RunWatchdog {
        fn drop(&mut self) {
            if let Some(finished) = self.finished.take() {
                let _ = finished.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    struct GuestMemory {
        partition: PartitionHandle,
        host: *mut c_void,
        mapped_len: usize,
        ram_len: usize,
    }

    impl GuestMemory {
        fn map(partition: PartitionHandle, bus: &mut MemoryBus) -> Result<Self, WhpError> {
            let ram_len = bus.len();
            let mapped_len = ram_len
                .checked_add(PAGE_SIZE - 1)
                .map(|length| length & !(PAGE_SIZE - 1))
                .filter(|length| *length != 0)
                .ok_or(WhpError::AllocateGuestMemory)?;
            // SAFETY: the requested allocation has explicit size and protection.
            let host = unsafe {
                VirtualAlloc(
                    ptr::null_mut(),
                    mapped_len,
                    MEM_COMMIT_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if host.is_null() {
                return Err(WhpError::AllocateGuestMemory);
            }
            // SAFETY: VirtualAlloc returned `mapped_len` writable bytes.
            let host_bytes = unsafe { slice::from_raw_parts_mut(host.cast::<u8>(), mapped_len) };
            host_bytes.fill(0);
            if bus.read_physical(0, &mut host_bytes[..ram_len]).is_err() {
                // SAFETY: host is the allocation just created above.
                let _ = unsafe { VirtualFree(host, 0, MEM_RELEASE) };
                return Err(WhpError::GuestMemoryAccess);
            }
            // SAFETY: VirtualAlloc is page aligned and both lengths are page multiples.
            let result = unsafe {
                WHvMapGpaRange(
                    partition,
                    host,
                    0,
                    mapped_len as u64,
                    MAP_READ_WRITE_EXECUTE,
                )
            };
            if result < 0 {
                // SAFETY: host is the allocation just created above.
                let _ = unsafe { VirtualFree(host, 0, MEM_RELEASE) };
                return Err(WhpError::MapGuestMemory(result));
            }
            Ok(Self {
                partition,
                host,
                mapped_len,
                ram_len,
            })
        }

        fn copy_back(&self, bus: &mut MemoryBus) -> Result<(), WhpError> {
            // SAFETY: this object owns a live mapping at least `ram_len` bytes long.
            let bytes = unsafe { slice::from_raw_parts(self.host.cast::<u8>(), self.ram_len) };
            bus.write_physical(0, bytes)
                .map_err(|_| WhpError::GuestMemoryAccess)
        }
    }

    impl Drop for GuestMemory {
        fn drop(&mut self) {
            // SAFETY: the exact mapping is still owned by this object.
            let _ = unsafe { WHvUnmapGpaRange(self.partition, 0, self.mapped_len as u64) };
            // SAFETY: host is the sole VirtualAlloc allocation owned here.
            let _ = unsafe { VirtualFree(self.host, 0, MEM_RELEASE) };
        }
    }

    struct InstructionEmulator(EmulatorHandle);

    impl InstructionEmulator {
        fn create() -> Result<Self, WhpError> {
            let callbacks = EmulatorCallbacks {
                size: mem::size_of::<EmulatorCallbacks>() as u32,
                reserved: 0,
                io: Some(io_callback),
                memory: Some(memory_callback),
                get_registers: Some(get_registers_callback),
                set_registers: Some(set_registers_callback),
                translate: Some(translate_callback),
            };
            let mut handle = ptr::null_mut();
            // SAFETY: callbacks remain valid function pointers for process lifetime.
            let result = unsafe { WHvEmulatorCreateEmulator(&callbacks, &mut handle) };
            if result < 0 {
                return Err(WhpError::CreateInstructionEmulator(result));
            }
            Ok(Self(handle))
        }

        fn emulate_io(
            &self,
            callbacks: &mut CallbackContext,
            context: &RunVpExitContext,
        ) -> Result<(), WhpError> {
            let mut status = 0u32;
            // SAFETY: the tagged run exit selected the I/O union member.
            let io = unsafe { &context.details.io_port_access };
            // SAFETY: all context pointers have the exact SDK layouts.
            let result = unsafe {
                WHvEmulatorTryIoEmulation(
                    self.0,
                    ptr::from_mut(callbacks).cast(),
                    &context.vp_context,
                    io,
                    &mut status,
                )
            };
            if result < 0 || status & 1 == 0 {
                return Err(WhpError::InstructionEmulation { result, status });
            }
            Ok(())
        }

        fn emulate_mmio(
            &self,
            callbacks: &mut CallbackContext,
            context: &RunVpExitContext,
        ) -> Result<(), WhpError> {
            let mut status = 0u32;
            // SAFETY: the tagged run exit selected the memory union member.
            let memory = unsafe { &context.details.memory_access };
            // SAFETY: all context pointers have the exact SDK layouts.
            let result = unsafe {
                WHvEmulatorTryMmioEmulation(
                    self.0,
                    ptr::from_mut(callbacks).cast(),
                    &context.vp_context,
                    memory,
                    &mut status,
                )
            };
            if result < 0 || status & 1 == 0 {
                return Err(WhpError::InstructionEmulation { result, status });
            }
            Ok(())
        }
    }

    impl Drop for InstructionEmulator {
        fn drop(&mut self) {
            // SAFETY: the handle is solely owned and no emulation call is active.
            let _ = unsafe { WHvEmulatorDestroyEmulator(self.0) };
        }
    }

    const _: () = assert!(mem::size_of::<SegmentRegister>() == 16);
    const _: () = assert!(mem::size_of::<RegisterValue>() == 16);
    const _: () = assert!(mem::size_of::<VpExitContext>() == 40);
    const _: () = assert!(mem::size_of::<MemoryAccessContext>() == 40);
    const _: () = assert!(mem::size_of::<IoPortAccessContext>() == 96);
    const _: () = assert!(mem::size_of::<ExceptionContext>() == 40);
    const _: () = assert!(mem::size_of::<RunVpExitContext>() == 224);
    const _: () = assert!(mem::size_of::<EmulatorCallbacks>() == 48);
    const _: () = assert!(mem::size_of::<InterruptControl>() == 16);

    #[link(name = "WinHvPlatform")]
    extern "system" {
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
        fn WHvGetVirtualProcessorRegisters(
            partition: PartitionHandle,
            index: u32,
            register_names: *const u32,
            register_count: u32,
            register_values: *mut RegisterValue,
        ) -> i32;
        fn WHvRunVirtualProcessor(
            partition: PartitionHandle,
            index: u32,
            exit_context: *mut c_void,
            exit_context_size: u32,
        ) -> i32;
        fn WHvCancelRunVirtualProcessor(partition: PartitionHandle, index: u32, flags: u32) -> i32;
        fn WHvTranslateGva(
            partition: PartitionHandle,
            index: u32,
            gva: u64,
            flags: u32,
            result: *mut TranslateResult,
            gpa: *mut u64,
        ) -> i32;
        fn WHvRequestInterrupt(
            partition: PartitionHandle,
            interrupt: *const InterruptControl,
            interrupt_size: u32,
        ) -> i32;
    }

    #[link(name = "WinHvEmulation")]
    extern "system" {
        fn WHvEmulatorCreateEmulator(
            callbacks: *const EmulatorCallbacks,
            emulator: *mut EmulatorHandle,
        ) -> i32;
        fn WHvEmulatorDestroyEmulator(emulator: EmulatorHandle) -> i32;
        fn WHvEmulatorTryIoEmulation(
            emulator: EmulatorHandle,
            context: *mut c_void,
            vp_context: *const VpExitContext,
            io_context: *const IoPortAccessContext,
            status: *mut u32,
        ) -> i32;
        fn WHvEmulatorTryMmioEmulation(
            emulator: EmulatorHandle,
            context: *mut c_void,
            vp_context: *const VpExitContext,
            memory_context: *const MemoryAccessContext,
            status: *mut u32,
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

    unsafe extern "system" fn io_callback(
        context: *mut c_void,
        access: *mut EmulatorIoAccess,
    ) -> i32 {
        if context.is_null() || access.is_null() {
            return E_FAIL;
        }
        // SAFETY: the emulator returns the exact context pointer supplied by the run loop.
        let callback = unsafe { &mut *context.cast::<CallbackContext>() };
        // SAFETY: WHP owns a live in/out access structure for this callback.
        let access = unsafe { &mut *access };
        let Ok(size) = u8::try_from(access.access_size) else {
            return E_FAIL;
        };
        if !matches!(size, 1 | 2 | 4) {
            return E_FAIL;
        }
        // SAFETY: callback.bus points at the exclusively borrowed machine bus.
        let bus = unsafe { &mut *callback.bus };
        if access.direction == 0 {
            access.data = bus.read_port(access.port, size);
        } else {
            bus.write_port(access.port, size, access.data);
        }
        S_OK
    }

    unsafe extern "system" fn memory_callback(
        context: *mut c_void,
        access: *mut EmulatorMemoryAccess,
    ) -> i32 {
        if context.is_null() || access.is_null() {
            return E_FAIL;
        }
        // SAFETY: these pointers are the live values supplied to the emulator.
        let callback = unsafe { &mut *context.cast::<CallbackContext>() };
        let access = unsafe { &mut *access };
        let size = usize::from(access.access_size);
        if !(1..=8).contains(&size) {
            return E_FAIL;
        }
        // SAFETY: callback.bus points at the exclusively borrowed machine bus.
        let bus = unsafe { &mut *callback.bus };
        let result = if access.direction == 0 {
            bus.read_physical(access.gpa_address, &mut access.data[..size])
        } else {
            bus.write_physical(access.gpa_address, &access.data[..size])
        };
        if result.is_ok() {
            S_OK
        } else {
            E_FAIL
        }
    }

    unsafe extern "system" fn get_registers_callback(
        context: *mut c_void,
        names: *const u32,
        count: u32,
        values: *mut RegisterValue,
    ) -> i32 {
        if context.is_null() {
            return E_FAIL;
        }
        // SAFETY: context was created by the run loop and remains live.
        let callback = unsafe { &*context.cast::<CallbackContext>() };
        // SAFETY: WHP owns the register arrays and supplies `count` elements.
        unsafe {
            WHvGetVirtualProcessorRegisters(
                callback.partition,
                callback.vp_index,
                names,
                count,
                values,
            )
        }
    }

    unsafe extern "system" fn set_registers_callback(
        context: *mut c_void,
        names: *const u32,
        count: u32,
        values: *const RegisterValue,
    ) -> i32 {
        if context.is_null() {
            return E_FAIL;
        }
        // SAFETY: context and register arrays are live for the callback duration.
        let callback = unsafe { &*context.cast::<CallbackContext>() };
        unsafe {
            WHvSetVirtualProcessorRegisters(
                callback.partition,
                callback.vp_index,
                names,
                count,
                values,
            )
        }
    }

    unsafe extern "system" fn translate_callback(
        context: *mut c_void,
        gva: u64,
        flags: u32,
        translation_code: *mut u32,
        gpa: *mut u64,
    ) -> i32 {
        if context.is_null() || translation_code.is_null() || gpa.is_null() {
            return E_FAIL;
        }
        // SAFETY: context and output pointers are live for this callback.
        let callback = unsafe { &*context.cast::<CallbackContext>() };
        let mut result = TranslateResult::default();
        let status = unsafe {
            WHvTranslateGva(
                callback.partition,
                callback.vp_index,
                gva,
                flags,
                &mut result,
                gpa,
            )
        };
        if status >= 0 {
            // SAFETY: checked non-null above; WHP expects only the result-code field.
            unsafe { *translation_code = result.code };
        }
        status
    }

    fn install_machine_registers(
        partition: PartitionHandle,
        machine: &Machine,
    ) -> Result<(), WhpError> {
        let state = &machine.cpu.state;
        let mut names = [0u32; 27];
        let mut values = [RegisterValue::default(); 27];
        for index in 0..16 {
            names[index] = index as u32;
            values[index] = RegisterValue::reg64(state.registers[index]);
        }
        names[16..].copy_from_slice(&[
            REGISTER_RIP,
            REGISTER_RFLAGS,
            REGISTER_ES,
            REGISTER_CS,
            REGISTER_SS,
            REGISTER_DS,
            REGISTER_FS,
            REGISTER_GS,
            REGISTER_CR0,
            REGISTER_CR2,
            REGISTER_CR3,
        ]);
        // Add CR4 and EFER by replacing two otherwise-unused trailing GPR
        // slots through a second call, keeping the first array compact.
        values[16] = RegisterValue::reg64(state.rip);
        values[17] = RegisterValue::reg64(state.rflags);
        let long_mode = state.efer & (1 << 10) != 0;
        let code_attributes = if long_mode { 0xA09B } else { 0x009B };
        let data_attributes = if long_mode { 0xC093 } else { 0x0093 };
        let code = SegmentRegister {
            base: 0,
            limit: if long_mode { u32::MAX } else { 0xFFFF },
            selector: state.cs,
            attributes: code_attributes,
        };
        let data = |selector| SegmentRegister {
            base: 0,
            limit: if long_mode { u32::MAX } else { 0xFFFF },
            selector,
            attributes: data_attributes,
        };
        values[18] = RegisterValue::segment(data(state.es));
        values[19] = RegisterValue::segment(code);
        values[20] = RegisterValue::segment(data(state.ss));
        values[21] = RegisterValue::segment(data(state.ds));
        values[22] = RegisterValue::segment(data(state.fs));
        values[23] = RegisterValue::segment(data(state.gs));
        values[24] = RegisterValue::reg64(state.cr0);
        values[25] = RegisterValue::reg64(state.cr2);
        values[26] = RegisterValue::reg64(state.cr3);
        // SAFETY: register names and values have identical fixed lengths.
        let result = unsafe {
            WHvSetVirtualProcessorRegisters(
                partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr(),
            )
        };
        if result < 0 {
            return Err(WhpError::SetRegisters(result));
        }
        let extra_names = [REGISTER_CR4, REGISTER_EFER];
        let extra_values = [
            RegisterValue::reg64(state.cr4),
            RegisterValue::reg64(state.efer),
        ];
        // SAFETY: two valid names have two matching values.
        let result = unsafe {
            WHvSetVirtualProcessorRegisters(
                partition,
                0,
                extra_names.as_ptr(),
                extra_names.len() as u32,
                extra_values.as_ptr(),
            )
        };
        if result < 0 {
            return Err(WhpError::SetRegisters(result));
        }
        Ok(())
    }

    fn request_interrupt(partition: PartitionHandle, bus: &mut MemoryBus) {
        let Some(vector) = bus.next_interrupt() else {
            return;
        };
        let interrupt = InterruptControl {
            control: 0,
            destination: 0,
            vector: u32::from(vector),
        };
        // SAFETY: this is a fixed, physical, edge-triggered interrupt request.
        let _ = unsafe {
            WHvRequestInterrupt(
                partition,
                &interrupt,
                mem::size_of::<InterruptControl>() as u32,
            )
        };
    }

    impl WhpPartition {
        pub fn create_machine(processor_count: u32) -> Result<Self, WhpError> {
            Self::create_accelerated(processor_count)
        }

        pub fn run_machine(
            &mut self,
            machine: &mut Machine,
            timeout: Duration,
            exit_limit: u64,
        ) -> Result<WhpRunSummary, WhpError> {
            if self.processor_count() == 0 || exit_limit == 0 {
                return Err(WhpError::ExecutionLimit);
            }
            let handle = self.raw_handle();
            let memory = GuestMemory::map(handle, &mut machine.bus)?;
            install_machine_registers(handle, machine)?;
            let emulator = InstructionEmulator::create()?;
            let mut callbacks = CallbackContext {
                partition: handle,
                vp_index: 0,
                bus: ptr::from_mut(&mut machine.bus),
            };

            let watchdog = RunWatchdog::start(handle, timeout);

            let mut exits = 0u64;
            let reason = loop {
                if exits == exit_limit {
                    break WhpRunReason::ExitLimit;
                }
                let mut context = RunVpExitContext::default();
                // SAFETY: output context exactly matches the WHP x64 ABI.
                let result = unsafe {
                    WHvRunVirtualProcessor(
                        handle,
                        0,
                        ptr::from_mut(&mut context).cast(),
                        mem::size_of::<RunVpExitContext>() as u32,
                    )
                };
                if result < 0 {
                    return Err(WhpError::RunProcessor(result));
                }
                exits += 1;
                match context.exit_reason {
                    EXIT_IO_PORT_ACCESS => emulator.emulate_io(&mut callbacks, &context)?,
                    EXIT_MEMORY_ACCESS => emulator.emulate_mmio(&mut callbacks, &context)?,
                    EXIT_APIC_EOI => {},
                    EXIT_HALT => {
                        machine.bus.tick(DEVICE_TICK_PER_EXIT);
                        request_interrupt(handle, &mut machine.bus);
                        if machine.serial_output().ends_with(b"xenith$ ") {
                            break WhpRunReason::Halted;
                        }
                    },
                    EXIT_CANCELED => break WhpRunReason::TimedOut,
                    EXIT_EXCEPTION => {
                        // SAFETY: the tagged exit selected the exception member.
                        let exception = unsafe { context.details.exception };
                        return Err(WhpError::GuestException {
                            vector: exception.exception_type,
                            error_code: exception.error_code,
                            parameter: exception.exception_parameter,
                            rip: context.vp_context.rip,
                            instruction_bytes: exception.instruction_bytes,
                            instruction_len: exception.instruction_byte_count,
                        });
                    },
                    other => {
                        let names = [4, REGISTER_CR2, REGISTER_CR3, REGISTER_GS, REGISTER_KERNEL_GS_BASE];
                        let mut values = [RegisterValue::default(); 5];
                        // SAFETY: each writable register value matches one valid name.
                        let result = unsafe {
                            WHvGetVirtualProcessorRegisters(
                                handle,
                                0,
                                names.as_ptr(),
                                names.len() as u32,
                                values.as_mut_ptr(),
                            )
                        };
                        if result < 0 {
                            values.fill(RegisterValue::default());
                        }
                        return Err(WhpError::UnexpectedMachineExit {
                            reason: other,
                            rip: context.vp_context.rip,
                            rflags: context.vp_context.rflags,
                            rsp: values[0].words[0],
                            cr2: values[1].words[0],
                            cr3: values[2].words[0],
                            gs_base: values[3].words[0],
                            kernel_gs_base: values[4].words[0],
                        });
                    },
                }
                if machine.serial_output().ends_with(b"xenith$ ") {
                    break WhpRunReason::ShellReady;
                }
                machine.bus.tick(DEVICE_TICK_PER_EXIT);
                request_interrupt(handle, &mut machine.bus);
            };
            drop(watchdog);
            memory.copy_back(&mut machine.bus)?;
            Ok(WhpRunSummary { reason, exits })
        }
    }
}

#[cfg(not(windows))]
impl WhpPartition {
    pub fn create_machine(_processor_count: u32) -> Result<Self, WhpError> {
        Err(WhpError::Unavailable)
    }

    pub fn run_machine(
        &mut self,
        _machine: &mut Machine,
        _timeout: Duration,
        _exit_limit: u64,
    ) -> Result<WhpRunSummary, WhpError> {
        Err(WhpError::Unavailable)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::time::Duration;

    use xenith_emu::{Machine, MachineConfig};

    use super::{WhpPartition, WhpRunReason};

    #[test]
    fn machine_runner_services_serial_io_and_watchdog_when_available() {
        if !WhpPartition::is_available() {
            return;
        }
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 2 * 1024 * 1024,
            instruction_limit: 32,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine
            .load_flat(
                0x1000,
                &[0xBA, 0xF8, 0x03, 0xB0, b'X', 0xEE, 0xF4],
                0x8_0000,
            )
            .expect("load flat WHP smoke program");
        machine.cpu.state.cs = 0;
        machine.cpu.state.ss = 0;
        let mut partition = WhpPartition::create_machine(1).expect("create accelerated partition");
        let summary = partition
            .run_machine(&mut machine, Duration::from_millis(100), 32)
            .expect("execute shared-machine WHP loop");
        assert_eq!(summary.reason, WhpRunReason::TimedOut);
        assert_eq!(machine.serial_output(), b"X");
    }
}

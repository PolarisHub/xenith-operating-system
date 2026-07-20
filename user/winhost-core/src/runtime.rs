//! Fixed-capacity NT object, handle, and service runtime.

use crate::{
    resolve_nt_service, AccessMask, ConsoleObject, EventState, GuestHandle, HandleEntry,
    HandleTable, MutantState, NtService, NtServiceCall, NtServiceReply, NtStatus, NtThreadId,
    NtWaitMode, ObjectId, ObjectTable, ObjectType, RuntimeObject, SemaphoreState, TimerState,
    WaitSatisfaction,
};

const EVENT_ALLOWED_ACCESS: AccessMask = AccessMask::EVENT_QUERY_STATE
    .union(AccessMask::EVENT_MODIFY_STATE)
    .union(AccessMask::SYNCHRONIZE);
const MUTANT_ALLOWED_ACCESS: AccessMask =
    AccessMask::MUTANT_QUERY_STATE.union(AccessMask::SYNCHRONIZE);
const SEMAPHORE_ALLOWED_ACCESS: AccessMask = AccessMask::SEMAPHORE_QUERY_STATE
    .union(AccessMask::SEMAPHORE_MODIFY_STATE)
    .union(AccessMask::SYNCHRONIZE);
const TIMER_ALLOWED_ACCESS: AccessMask = AccessMask::TIMER_QUERY_STATE
    .union(AccessMask::TIMER_MODIFY_STATE)
    .union(AccessMask::SYNCHRONIZE);

/// Fixed-capacity clean-room NT runtime.
///
/// The runtime owns no heap storage and performs no syscalls. Handles and
/// object slots have independent generations; handle publication, duplication,
/// and rollback keep the object reference count exact.
pub struct NtRuntime<const H: usize, const O: usize> {
    handles: HandleTable<H>,
    objects: ObjectTable<O>,
}

impl<const H: usize, const O: usize> NtRuntime<H, O> {
    /// Creates an empty runtime after validating both const-generic capacities.
    pub const fn try_new() -> Result<Self, NtStatus> {
        let handles = match HandleTable::try_new() {
            Ok(table) => table,
            Err(error) => return Err(error.status()),
        };
        let objects = match ObjectTable::try_new() {
            Ok(table) => table,
            Err(error) => return Err(error.status()),
        };
        Ok(Self { handles, objects })
    }

    /// Returns the number of live guest handles.
    #[must_use]
    pub const fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Returns the number of live runtime objects.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Returns the reference count associated with a live handle's object.
    pub fn object_reference_count(&self, handle: GuestHandle) -> Result<u32, NtStatus> {
        let entry = self
            .handles
            .reference(handle, None, AccessMask::NONE)
            .map_err(|error| error.status())?;
        self.objects
            .reference_count(ObjectId::from_raw(entry.object_id))
            .map_err(|error| error.status())
    }

    /// Installs a borrowed console descriptor with exact read/write rights.
    pub fn insert_console(
        &mut self,
        descriptor: i32,
        readable: bool,
        writable: bool,
        inheritable: bool,
    ) -> Result<GuestHandle, NtStatus> {
        let console = ConsoleObject::try_new(descriptor, readable, writable)
            .map_err(|error| error.status())?;
        let mut access = AccessMask::NONE;
        if readable {
            access = access.union(AccessMask::GENERIC_READ);
        }
        if writable {
            access = access.union(AccessMask::GENERIC_WRITE);
        }
        self.insert_object_handle(RuntimeObject::Console(console), access, inheritable)
    }

    /// Resolves a console descriptor after checked type and access validation.
    pub fn console_descriptor(&self, handle: GuestHandle, write: bool) -> Result<i32, NtStatus> {
        let requested = if write {
            AccessMask::GENERIC_WRITE
        } else {
            AccessMask::GENERIC_READ
        };
        let entry = self
            .handles
            .reference(handle, Some(ObjectType::Console), requested)
            .map_err(|error| error.status())?;
        let object = self
            .objects
            .reference(
                ObjectId::from_raw(entry.object_id),
                Some(ObjectType::Console),
            )
            .map_err(|error| error.status())?;
        let RuntimeObject::Console(console) = object else {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        if (write && !console.is_writable()) || (!write && !console.is_readable()) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        Ok(console.descriptor())
    }

    /// Closes one handle and releases exactly one object reference.
    pub fn close(&mut self, handle: GuestHandle) -> Result<Option<RuntimeObject>, NtStatus> {
        let entry = self
            .handles
            .reference(handle, None, AccessMask::NONE)
            .map_err(|error| error.status())?;
        let id = ObjectId::from_raw(entry.object_id);
        self.objects
            .reference(id, Some(entry.object_type))
            .map_err(|error| error.status())?;
        self.handles.close(handle).map_err(|error| error.status())?;
        self.objects.release(id).map_err(|error| error.status())
    }

    /// Duplicates a handle after retaining its object, rolling back on failure.
    pub fn duplicate(
        &mut self,
        source: GuestHandle,
        desired_access: Option<AccessMask>,
        inheritable: Option<bool>,
    ) -> Result<GuestHandle, NtStatus> {
        let entry = self
            .handles
            .reference(source, None, AccessMask::NONE)
            .map_err(|error| error.status())?;
        if desired_access.is_some_and(|desired| !entry.access.contains(desired)) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let id = ObjectId::from_raw(entry.object_id);
        self.objects
            .reference(id, Some(entry.object_type))
            .map_err(|error| error.status())?;
        self.objects.retain(id).map_err(|error| error.status())?;
        match self.handles.duplicate(source, desired_access, inheritable) {
            Ok(handle) => Ok(handle),
            Err(error) => {
                let rollback = self.objects.release(id);
                debug_assert!(rollback.is_ok());
                Err(error.status())
            },
        }
    }

    /// Resolves and dispatches a service by module and exact export symbol.
    ///
    /// Unknown names always return `STATUS_NOT_IMPLEMENTED`. A known name paired
    /// with the wrong typed call returns `STATUS_INVALID_PARAMETER`.
    pub fn dispatch_symbol(
        &mut self,
        module: &[u8],
        symbol: &[u8],
        call: NtServiceCall,
    ) -> NtServiceReply {
        let service = resolve_nt_service(module, symbol);
        if service == NtService::Unknown {
            return NtServiceReply::status(NtStatus::NOT_IMPLEMENTED);
        }
        if service != call.service() {
            return NtServiceReply::status(NtStatus::INVALID_PARAMETER);
        }
        self.dispatch(call)
    }

    /// Dispatches one already resolved, typed internal service call.
    pub fn dispatch(&mut self, call: NtServiceCall) -> NtServiceReply {
        match call {
            NtServiceCall::Close { handle } => match self.close(handle) {
                Ok(_) => NtServiceReply::status(NtStatus::SUCCESS),
                Err(status) => NtServiceReply::status(status),
            },
            NtServiceCall::DuplicateObject {
                source,
                desired_access,
                inheritable,
            } => match self.duplicate(source, desired_access, inheritable) {
                Ok(handle) => NtServiceReply::handle(handle),
                Err(status) => NtServiceReply::status(status),
            },
            NtServiceCall::CreateEvent {
                kind,
                initial_state,
                access,
                inheritable,
            } => self.create_event(kind, initial_state, access, inheritable),
            NtServiceCall::SetEvent { handle } => self.set_event(handle, true),
            NtServiceCall::ResetEvent { handle } => self.set_event(handle, false),
            NtServiceCall::CreateMutant {
                initial_owner,
                access,
                inheritable,
            } => self.create_mutant(initial_owner, access, inheritable),
            NtServiceCall::ReleaseMutant { handle, thread } => self.release_mutant(handle, thread),
            NtServiceCall::CreateSemaphore {
                initial,
                limit,
                access,
                inheritable,
            } => self.create_semaphore(initial, limit, access, inheritable),
            NtServiceCall::ReleaseSemaphore {
                handle,
                release_count,
            } => self.release_semaphore(handle, release_count),
            NtServiceCall::CreateTimer {
                kind,
                access,
                inheritable,
            } => self.create_timer(kind, access, inheritable),
            NtServiceCall::SetTimer {
                handle,
                now_ticks,
                delay_ticks,
                period_ticks,
            } => self.set_timer(handle, now_ticks, delay_ticks, period_ticks),
            NtServiceCall::CancelTimer { handle } => self.cancel_timer(handle),
            NtServiceCall::WaitForSingleObject {
                handle,
                thread,
                now_ticks,
                mode,
            } => self.wait_single(handle, thread, now_ticks, mode),
        }
    }

    /// Marks all mutants owned by a terminating thread as abandoned.
    pub fn abandon_thread(&mut self, thread: NtThreadId) -> usize {
        self.objects.abandon_mutants(thread)
    }

    fn create_event(
        &mut self,
        kind: crate::EventKind,
        initial: bool,
        access: AccessMask,
        inheritable: bool,
    ) -> NtServiceReply {
        if let Err(status) = validate_access(access, EVENT_ALLOWED_ACCESS) {
            return NtServiceReply::status(status);
        }
        match self.insert_object_handle(
            RuntimeObject::Event(EventState::new(kind, initial)),
            access,
            inheritable,
        ) {
            Ok(handle) => NtServiceReply::handle(handle),
            Err(status) => NtServiceReply::status(status),
        }
    }

    fn set_event(&mut self, handle: GuestHandle, signaled: bool) -> NtServiceReply {
        let object =
            match self.object_mut(handle, ObjectType::Event, AccessMask::EVENT_MODIFY_STATE) {
                Ok(object) => object,
                Err(status) => return NtServiceReply::status(status),
            };
        let RuntimeObject::Event(event) = object else {
            return NtServiceReply::status(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        NtServiceReply::boolean(if signaled { event.set() } else { event.reset() })
    }

    fn create_mutant(
        &mut self,
        owner: Option<NtThreadId>,
        access: AccessMask,
        inheritable: bool,
    ) -> NtServiceReply {
        if let Err(status) = validate_access(access, MUTANT_ALLOWED_ACCESS) {
            return NtServiceReply::status(status);
        }
        match self.insert_object_handle(
            RuntimeObject::Mutant(MutantState::new(owner)),
            access,
            inheritable,
        ) {
            Ok(handle) => NtServiceReply::handle(handle),
            Err(status) => NtServiceReply::status(status),
        }
    }

    fn release_mutant(&mut self, handle: GuestHandle, thread: NtThreadId) -> NtServiceReply {
        let object =
            match self.object_mut(handle, ObjectType::Mutant, AccessMask::MUTANT_QUERY_STATE) {
                Ok(object) => object,
                Err(status) => return NtServiceReply::status(status),
            };
        let RuntimeObject::Mutant(mutant) = object else {
            return NtServiceReply::status(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        match mutant.release(thread) {
            Ok(previous) => NtServiceReply::count(previous),
            Err(error) => NtServiceReply::status(error.status()),
        }
    }

    fn create_semaphore(
        &mut self,
        initial: u32,
        limit: u32,
        access: AccessMask,
        inheritable: bool,
    ) -> NtServiceReply {
        if let Err(status) = validate_access(access, SEMAPHORE_ALLOWED_ACCESS) {
            return NtServiceReply::status(status);
        }
        let semaphore = match SemaphoreState::try_new(initial, limit) {
            Ok(semaphore) => semaphore,
            Err(error) => return NtServiceReply::status(error.status()),
        };
        match self.insert_object_handle(RuntimeObject::Semaphore(semaphore), access, inheritable) {
            Ok(handle) => NtServiceReply::handle(handle),
            Err(status) => NtServiceReply::status(status),
        }
    }

    fn release_semaphore(&mut self, handle: GuestHandle, count: u32) -> NtServiceReply {
        let object = match self.object_mut(
            handle,
            ObjectType::Semaphore,
            AccessMask::SEMAPHORE_MODIFY_STATE,
        ) {
            Ok(object) => object,
            Err(status) => return NtServiceReply::status(status),
        };
        let RuntimeObject::Semaphore(semaphore) = object else {
            return NtServiceReply::status(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        match semaphore.release(count) {
            Ok(previous) => NtServiceReply::count(previous),
            Err(error) => NtServiceReply::status(error.status()),
        }
    }

    fn create_timer(
        &mut self,
        kind: crate::TimerKind,
        access: AccessMask,
        inheritable: bool,
    ) -> NtServiceReply {
        if let Err(status) = validate_access(access, TIMER_ALLOWED_ACCESS) {
            return NtServiceReply::status(status);
        }
        match self.insert_object_handle(
            RuntimeObject::Timer(TimerState::new(kind)),
            access,
            inheritable,
        ) {
            Ok(handle) => NtServiceReply::handle(handle),
            Err(status) => NtServiceReply::status(status),
        }
    }

    fn set_timer(
        &mut self,
        handle: GuestHandle,
        now: u64,
        delay: u64,
        period: u64,
    ) -> NtServiceReply {
        let object =
            match self.object_mut(handle, ObjectType::Timer, AccessMask::TIMER_MODIFY_STATE) {
                Ok(object) => object,
                Err(status) => return NtServiceReply::status(status),
            };
        let RuntimeObject::Timer(timer) = object else {
            return NtServiceReply::status(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        match timer.set_relative(now, delay, period) {
            Ok(previous) => NtServiceReply::boolean(previous),
            Err(error) => NtServiceReply::status(error.status()),
        }
    }

    fn cancel_timer(&mut self, handle: GuestHandle) -> NtServiceReply {
        let object =
            match self.object_mut(handle, ObjectType::Timer, AccessMask::TIMER_MODIFY_STATE) {
                Ok(object) => object,
                Err(status) => return NtServiceReply::status(status),
            };
        let RuntimeObject::Timer(timer) = object else {
            return NtServiceReply::status(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        NtServiceReply::boolean(timer.cancel())
    }

    fn wait_single(
        &mut self,
        handle: GuestHandle,
        thread: NtThreadId,
        now: u64,
        mode: NtWaitMode,
    ) -> NtServiceReply {
        let object = match self.object_mut(handle, ObjectType::Invalid, AccessMask::SYNCHRONIZE) {
            Ok(object) => object,
            Err(NtStatus::OBJECT_TYPE_MISMATCH) => {
                // `Invalid` is a sentinel asking object_mut to skip type checks.
                unreachable!()
            },
            Err(status) => return NtServiceReply::status(status),
        };
        let result = match object {
            RuntimeObject::Event(event) => Ok(event.try_wait()),
            RuntimeObject::Mutant(mutant) => mutant.try_wait(thread),
            RuntimeObject::Semaphore(semaphore) => Ok(semaphore.try_wait()),
            RuntimeObject::Timer(timer) => timer.try_wait(now),
            _ => return NtServiceReply::status(NtStatus::OBJECT_TYPE_MISMATCH),
        };
        match result {
            Ok(WaitSatisfaction::Satisfied) => NtServiceReply::status(NtStatus::SUCCESS),
            Ok(WaitSatisfaction::Abandoned) => NtServiceReply::status(NtStatus::ABANDONED),
            Ok(WaitSatisfaction::WouldBlock) if mode == NtWaitMode::Poll => {
                NtServiceReply::status(NtStatus::TIMEOUT)
            },
            Ok(WaitSatisfaction::WouldBlock) => NtServiceReply::status(NtStatus::NOT_IMPLEMENTED),
            Err(error) => NtServiceReply::status(error.status()),
        }
    }

    fn insert_object_handle(
        &mut self,
        object: RuntimeObject,
        access: AccessMask,
        inheritable: bool,
    ) -> Result<GuestHandle, NtStatus> {
        let object_type = object.object_type();
        let id = self
            .objects
            .insert(object)
            .map_err(|error| error.status())?;
        let entry = HandleEntry {
            object_id: id.raw(),
            object_type,
            access,
            inheritable,
        };
        match self.handles.insert(entry) {
            Ok(handle) => Ok(handle),
            Err(error) => {
                let rollback = self.objects.release(id);
                debug_assert!(matches!(rollback, Ok(Some(_))));
                Err(error.status())
            },
        }
    }

    fn object_mut(
        &mut self,
        handle: GuestHandle,
        expected: ObjectType,
        access: AccessMask,
    ) -> Result<&mut RuntimeObject, NtStatus> {
        let expected_handle = (expected != ObjectType::Invalid).then_some(expected);
        let entry = self
            .handles
            .reference(handle, expected_handle, access)
            .map_err(|error| error.status())?;
        self.objects
            .reference_mut(
                ObjectId::from_raw(entry.object_id),
                expected_handle.or(Some(entry.object_type)),
            )
            .map_err(|error| error.status())
    }
}

fn validate_access(access: AccessMask, allowed: AccessMask) -> Result<(), NtStatus> {
    if access.bits() & !allowed.bits() != 0 {
        Err(NtStatus::ACCESS_DENIED)
    } else {
        Ok(())
    }
}

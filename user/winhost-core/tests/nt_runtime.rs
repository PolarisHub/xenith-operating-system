use xenith_winhost_core::{
    resolve_nt_service, AccessMask, ConsoleObject, EventKind, EventState, GuestHandle, NtRuntime,
    NtService, NtServiceCall, NtServiceReply, NtServiceValue, NtStatus, NtThreadId, NtWaitMode,
    ObjectError, ObjectId, ObjectTable, ObjectType, RuntimeObject, SemaphoreState, SyncError,
    TimerKind, TimerState, WaitSatisfaction,
};

fn thread(raw: u64) -> NtThreadId {
    NtThreadId::try_from_raw(raw).unwrap()
}

fn reply_handle(reply: NtServiceReply) -> GuestHandle {
    assert_eq!(reply.status, NtStatus::SUCCESS);
    assert!(matches!(reply.value, NtServiceValue::Handle(_)));
    match reply.value {
        NtServiceValue::Handle(handle) => handle,
        _ => GuestHandle::NULL,
    }
}

fn create_event<const H: usize, const O: usize>(
    runtime: &mut NtRuntime<H, O>,
    kind: EventKind,
    initial_state: bool,
    access: AccessMask,
) -> GuestHandle {
    reply_handle(runtime.dispatch(NtServiceCall::CreateEvent {
        kind,
        initial_state,
        access,
        inheritable: false,
    }))
}

#[test]
fn symbolic_service_catalog_is_exact_and_build_number_independent() {
    let catalog: [(NtService, &[u8]); 13] = [
        (NtService::Close, b"NtClose"),
        (NtService::DuplicateObject, b"NtDuplicateObject"),
        (NtService::CreateEvent, b"NtCreateEvent"),
        (NtService::SetEvent, b"NtSetEvent"),
        (NtService::ResetEvent, b"NtResetEvent"),
        (NtService::CreateMutant, b"NtCreateMutant"),
        (NtService::ReleaseMutant, b"NtReleaseMutant"),
        (NtService::CreateSemaphore, b"NtCreateSemaphore"),
        (NtService::ReleaseSemaphore, b"NtReleaseSemaphore"),
        (NtService::CreateTimer, b"NtCreateTimer"),
        (NtService::SetTimer, b"NtSetTimer"),
        (NtService::CancelTimer, b"NtCancelTimer"),
        (NtService::WaitForSingleObject, b"NtWaitForSingleObject"),
    ];
    for (service, symbol) in catalog {
        assert_eq!(service.symbol(), symbol);
        assert_eq!(resolve_nt_service(b"NTDLL.DLL", symbol), service);
        assert_eq!(resolve_nt_service(b"ntdll.dll", symbol), service);
    }

    assert_eq!(NtService::Unknown.symbol(), b"");
    assert_eq!(
        resolve_nt_service(b"KERNEL32.DLL", b"NtClose"),
        NtService::Unknown
    );
    assert_eq!(
        resolve_nt_service(b"NTDLL.DLL", b"ntclose"),
        NtService::Unknown
    );
    assert_eq!(
        resolve_nt_service(b"NTDLL.DLL", b"NtFutureService"),
        NtService::Unknown
    );
    assert_eq!(resolve_nt_service(b"", b"NtClose"), NtService::Unknown);
}

#[test]
fn unknown_and_mismatched_symbol_dispatch_fails_closed() {
    let mut runtime = NtRuntime::<4, 4>::try_new().unwrap();
    let call = NtServiceCall::Close {
        handle: GuestHandle::from_raw(0x1001),
    };
    assert_eq!(
        runtime.dispatch_symbol(b"NTDLL.DLL", b"NtFutureService", call),
        NtServiceReply::status(NtStatus::NOT_IMPLEMENTED)
    );
    assert_eq!(
        runtime.dispatch_symbol(b"OTHER.DLL", b"NtClose", call),
        NtServiceReply::status(NtStatus::NOT_IMPLEMENTED)
    );
    assert_eq!(
        runtime.dispatch_symbol(b"NTDLL.DLL", b"NtSetEvent", call),
        NtServiceReply::status(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(runtime.handle_count(), 0);
    assert_eq!(runtime.object_count(), 0);
}

#[test]
fn event_wait_reset_type_and_access_checks_are_deterministic() {
    let mut runtime = NtRuntime::<8, 8>::try_new().unwrap();
    let event_access = AccessMask::EVENT_MODIFY_STATE.union(AccessMask::SYNCHRONIZE);
    let event = create_event(&mut runtime, EventKind::Notification, false, event_access);
    let caller = thread(1);

    assert_eq!(
        runtime.dispatch(NtServiceCall::WaitForSingleObject {
            handle: event,
            thread: caller,
            now_ticks: 0,
            mode: NtWaitMode::Poll,
        }),
        NtServiceReply::status(NtStatus::TIMEOUT)
    );
    assert_eq!(
        runtime.dispatch(NtServiceCall::WaitForSingleObject {
            handle: event,
            thread: caller,
            now_ticks: 0,
            mode: NtWaitMode::Blocking,
        }),
        NtServiceReply::status(NtStatus::NOT_IMPLEMENTED)
    );
    assert_eq!(
        runtime.dispatch(NtServiceCall::SetEvent { handle: event }),
        NtServiceReply::boolean(false)
    );
    for _ in 0..2 {
        assert_eq!(
            runtime.dispatch(NtServiceCall::WaitForSingleObject {
                handle: event,
                thread: caller,
                now_ticks: 0,
                mode: NtWaitMode::Poll,
            }),
            NtServiceReply::status(NtStatus::SUCCESS)
        );
    }
    assert_eq!(
        runtime.dispatch(NtServiceCall::ResetEvent { handle: event }),
        NtServiceReply::boolean(true)
    );

    let narrowed = reply_handle(runtime.dispatch(NtServiceCall::DuplicateObject {
        source: event,
        desired_access: Some(AccessMask::SYNCHRONIZE),
        inheritable: Some(true),
    }));
    assert_eq!(runtime.object_reference_count(event), Ok(2));
    assert_eq!(
        runtime.dispatch(NtServiceCall::SetEvent { handle: narrowed }),
        NtServiceReply::status(NtStatus::ACCESS_DENIED)
    );

    let semaphore = reply_handle(runtime.dispatch(NtServiceCall::CreateSemaphore {
        initial: 0,
        limit: 1,
        access: AccessMask::SEMAPHORE_MODIFY_STATE,
        inheritable: false,
    }));
    assert_eq!(
        runtime.dispatch(NtServiceCall::SetEvent { handle: semaphore }),
        NtServiceReply::status(NtStatus::OBJECT_TYPE_MISMATCH)
    );
    assert_eq!(
        runtime.dispatch(NtServiceCall::SetEvent {
            handle: GuestHandle::NULL,
        }),
        NtServiceReply::status(NtStatus::INVALID_HANDLE)
    );
}

#[test]
fn duplicate_close_and_full_table_rollbacks_preserve_lifetimes() {
    let mut runtime = NtRuntime::<2, 3>::try_new().unwrap();
    let source = runtime.insert_console(7, true, true, false).unwrap();
    let duplicate = runtime
        .duplicate(source, Some(AccessMask::GENERIC_READ), Some(true))
        .unwrap();
    assert_eq!(runtime.handle_count(), 2);
    assert_eq!(runtime.object_count(), 1);
    assert_eq!(runtime.object_reference_count(source), Ok(2));
    assert_eq!(runtime.console_descriptor(duplicate, false), Ok(7));
    assert_eq!(
        runtime.console_descriptor(duplicate, true),
        Err(NtStatus::ACCESS_DENIED)
    );

    assert_eq!(
        runtime.duplicate(source, Some(AccessMask::GENERIC_ALL), None),
        Err(NtStatus::ACCESS_DENIED)
    );
    assert_eq!(runtime.object_reference_count(source), Ok(2));
    assert_eq!(
        runtime.duplicate(source, None, None),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(runtime.object_reference_count(source), Ok(2));

    let failed_create = runtime.dispatch(NtServiceCall::CreateEvent {
        kind: EventKind::Notification,
        initial_state: false,
        access: AccessMask::NONE,
        inheritable: false,
    });
    assert_eq!(failed_create.status, NtStatus::INSUFFICIENT_RESOURCES);
    assert_eq!(runtime.object_count(), 1);

    assert!(runtime.close(source).unwrap().is_none());
    assert_eq!(runtime.object_count(), 1);
    assert_eq!(
        runtime.console_descriptor(source, false),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert!(matches!(
        runtime.close(duplicate),
        Ok(Some(RuntimeObject::Console(_)))
    ));
    assert_eq!(runtime.handle_count(), 0);
    assert_eq!(runtime.object_count(), 0);
    assert_eq!(runtime.close(duplicate), Err(NtStatus::INVALID_HANDLE));
}

#[test]
fn semaphore_mutant_and_timer_subset_is_transactional() {
    let mut semaphore = SemaphoreState::try_new(1, 2).unwrap();
    assert_eq!(semaphore.try_wait(), WaitSatisfaction::Satisfied);
    assert_eq!(semaphore.try_wait(), WaitSatisfaction::WouldBlock);
    assert_eq!(semaphore.release(1), Ok(0));
    assert_eq!(semaphore.release(2), Err(SyncError::SemaphoreLimitExceeded));
    assert_eq!(semaphore.count(), 1);
    assert_eq!(semaphore.release(0), Err(SyncError::InvalidParameter));
    assert_eq!(
        SemaphoreState::try_new(2, 1),
        Err(SyncError::InvalidParameter)
    );

    let first = thread(1);
    let second = thread(2);
    let mut runtime = NtRuntime::<8, 8>::try_new().unwrap();
    let mutant = reply_handle(runtime.dispatch(NtServiceCall::CreateMutant {
        initial_owner: Some(first),
        access: AccessMask::MUTANT_QUERY_STATE.union(AccessMask::SYNCHRONIZE),
        inheritable: false,
    }));
    assert_eq!(
        runtime.dispatch(NtServiceCall::ReleaseMutant {
            handle: mutant,
            thread: second,
        }),
        NtServiceReply::status(NtStatus::MUTANT_NOT_OWNED)
    );
    assert_eq!(runtime.abandon_thread(first), 1);
    assert_eq!(
        runtime.dispatch(NtServiceCall::WaitForSingleObject {
            handle: mutant,
            thread: second,
            now_ticks: 0,
            mode: NtWaitMode::Poll,
        }),
        NtServiceReply::status(NtStatus::ABANDONED)
    );
    assert_eq!(
        runtime.dispatch(NtServiceCall::WaitForSingleObject {
            handle: mutant,
            thread: first,
            now_ticks: 0,
            mode: NtWaitMode::Poll,
        }),
        NtServiceReply::status(NtStatus::TIMEOUT)
    );

    let mut timer = TimerState::new(TimerKind::Synchronization);
    assert_eq!(timer.set_relative(10, 5, 0), Ok(false));
    assert_eq!(timer.try_wait(14), Ok(WaitSatisfaction::WouldBlock));
    assert_eq!(timer.try_wait(15), Ok(WaitSatisfaction::Satisfied));
    assert_eq!(timer.try_wait(15), Ok(WaitSatisfaction::WouldBlock));
    assert_eq!(
        timer.set_relative(u64::MAX, 1, 0),
        Err(SyncError::IntegerOverflow)
    );
    assert!(!timer.is_active());

    assert_eq!(timer.set_relative(u64::MAX - 1, 0, 1), Ok(false));
    assert_eq!(timer.try_wait(u64::MAX), Err(SyncError::IntegerOverflow));
    assert_eq!(timer.deadline_ticks(), Some(u64::MAX - 1));
}

#[test]
fn auto_reset_and_notification_state_machines_have_distinct_consumption() {
    let mut auto = EventState::new(EventKind::Synchronization, true);
    assert_eq!(auto.try_wait(), WaitSatisfaction::Satisfied);
    assert_eq!(auto.try_wait(), WaitSatisfaction::WouldBlock);

    let mut notification_timer = TimerState::new(TimerKind::Notification);
    assert_eq!(notification_timer.set_relative(100, 0, 0), Ok(false));
    assert_eq!(
        notification_timer.try_wait(100),
        Ok(WaitSatisfaction::Satisfied)
    );
    assert_eq!(
        notification_timer.try_wait(100),
        Ok(WaitSatisfaction::Satisfied)
    );
}

#[test]
fn object_ids_are_typed_reference_counted_and_generation_safe() {
    let mut objects = ObjectTable::<1>::try_new().unwrap();
    let old = objects
        .insert(RuntimeObject::Event(EventState::new(
            EventKind::Notification,
            false,
        )))
        .unwrap();
    assert_eq!(old.raw(), 0x1_0001);
    assert_eq!(objects.reference_count(old), Ok(1));
    assert!(matches!(
        objects.reference(old, Some(ObjectType::Timer)),
        Err(ObjectError::TypeMismatch {
            expected: ObjectType::Timer,
            actual: ObjectType::Event,
        })
    ));
    assert_eq!(objects.retain(old), Ok(2));
    assert_eq!(objects.release(old), Ok(None));
    assert!(matches!(
        objects.release(old),
        Ok(Some(RuntimeObject::Event(_)))
    ));
    assert_eq!(
        objects.reference(old, None),
        Err(ObjectError::InvalidObjectId)
    );

    let current = objects
        .insert(RuntimeObject::Timer(TimerState::new(
            TimerKind::Notification,
        )))
        .unwrap();
    assert_ne!(current, old);
    assert_eq!(
        objects.reference(old, None),
        Err(ObjectError::InvalidObjectId)
    );
    assert!(matches!(
        objects.reference(current, Some(ObjectType::Timer)),
        Ok(RuntimeObject::Timer(_))
    ));
    assert_eq!(
        objects.reference(ObjectId::NULL, None),
        Err(ObjectError::InvalidObjectId)
    );
    assert_eq!(
        objects.reference(ObjectId::from_raw(u64::MAX), None),
        Err(ObjectError::InvalidObjectId)
    );
}

#[test]
fn invalid_object_construction_and_access_masks_fail_without_publication() {
    assert_eq!(
        ConsoleObject::try_new(-1, true, false),
        Err(ObjectError::InvalidObject)
    );
    assert_eq!(
        ConsoleObject::try_new(0, false, false),
        Err(ObjectError::InvalidObject)
    );

    let mut runtime = NtRuntime::<2, 2>::try_new().unwrap();
    let reply = runtime.dispatch(NtServiceCall::CreateTimer {
        kind: TimerKind::Notification,
        access: AccessMask::GENERIC_ALL,
        inheritable: false,
    });
    assert_eq!(reply, NtServiceReply::status(NtStatus::ACCESS_DENIED));
    assert_eq!(runtime.handle_count(), 0);
    assert_eq!(runtime.object_count(), 0);
}

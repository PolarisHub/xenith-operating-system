use core::mem::size_of;

use xenith_windrv_core::{
    DeviceId, IoAccess, IoControlCode, IoMethod, MajorFunction, RequestError, RequestId,
    RequestPool, RequestState, MAX_IO_TRANSFER_BYTES, MAX_REQUESTS,
};
use xenith_winhost_core::NtStatus;

const DEVICE: DeviceId = DeviceId::from_raw(0x101);

#[test]
fn request_capacities_and_transfer_budget_are_bounded() {
    assert!(matches!(
        RequestPool::<0>::try_new(),
        Err(RequestError::InvalidCapacity { .. })
    ));
    assert!(RequestPool::<MAX_REQUESTS>::try_new().is_ok());
    assert!(matches!(
        RequestPool::<{ MAX_REQUESTS + 1 }>::try_new(),
        Err(RequestError::InvalidCapacity { capacity, maximum: MAX_REQUESTS })
            if capacity == MAX_REQUESTS + 1
    ));
    assert!(
        size_of::<RequestPool<MAX_REQUESTS>>() <= 128 * 1024,
        "maximum inline request pool must stay below the audited stack budget"
    );

    let mut pool = RequestPool::<1>::try_new().unwrap();
    assert_eq!(
        pool.allocate(
            DEVICE,
            MajorFunction::Write,
            0,
            None,
            MAX_IO_TRANSFER_BYTES,
            1,
        ),
        Err(RequestError::TransferTooLarge)
    );
    assert_eq!(
        pool.allocate(
            DEVICE,
            MajorFunction::Write,
            0,
            None,
            usize::MAX,
            usize::MAX,
        ),
        Err(RequestError::TransferTooLarge)
    );
    for malformed in [
        DeviceId::NULL,
        DeviceId::from_raw(1),
        DeviceId::from_raw(u32::MAX),
    ] {
        assert_eq!(
            pool.allocate(malformed, MajorFunction::Create, 0, None, 0, 0),
            Err(RequestError::InvalidDevice)
        );
    }
    assert_eq!(
        RequestError::TransferTooLarge.status(),
        NtStatus::INVALID_PARAMETER
    );
    assert_eq!(
        RequestError::InvalidDevice.status(),
        NtStatus::INVALID_HANDLE
    );
    assert_eq!(
        RequestError::InvalidCompletionStatus.status(),
        NtStatus::INVALID_PARAMETER
    );
}

#[test]
fn ioctl_presence_must_match_major_function() {
    let code = IoControlCode::new(0x22, 0x800, IoMethod::Buffered, IoAccess::Any).unwrap();
    let mut pool = RequestPool::<2>::try_new().unwrap();
    assert_eq!(
        pool.allocate(DEVICE, MajorFunction::DeviceControl, 0, None, 0, 0),
        Err(RequestError::InvalidControlCode)
    );
    assert_eq!(
        pool.allocate(DEVICE, MajorFunction::Read, 0, Some(code), 0, 0),
        Err(RequestError::InvalidControlCode)
    );
}

#[test]
fn synchronous_request_has_transactional_lifecycle() {
    let mut pool = RequestPool::<1>::try_new().unwrap();
    let id = pool
        .allocate(DEVICE, MajorFunction::Read, 0, None, 0, 32)
        .unwrap();
    assert_eq!(pool.request(id).unwrap().state, RequestState::Allocated);
    assert!(matches!(
        pool.complete(id, NtStatus::SUCCESS, 1),
        Err(RequestError::InvalidState {
            state: RequestState::Allocated
        })
    ));
    pool.mark_dispatched(id).unwrap();
    pool.complete(id, NtStatus::SUCCESS, 12).unwrap();
    let completion = pool.reap(id).unwrap();
    assert_eq!(completion.device, DEVICE);
    assert_eq!(completion.major, MajorFunction::Read);
    assert_eq!(completion.minor, 0);
    assert_eq!(completion.control_code, None);
    assert_eq!(completion.input_len, 0);
    assert_eq!(completion.output_len, 32);
    assert_eq!(completion.status, NtStatus::SUCCESS);
    assert_eq!(completion.information, 12);
    assert!(!completion.cancel_requested);
    assert!(pool.is_empty());
    assert_eq!(pool.request(id), Err(RequestError::InvalidRequest));
}

#[test]
fn asynchronous_pending_and_cancel_race_complete_once() {
    let mut pool = RequestPool::<1>::try_new().unwrap();
    let id = pool
        .allocate(DEVICE, MajorFunction::Write, 0, None, 24, 0)
        .unwrap();
    pool.mark_dispatched(id).unwrap();
    pool.mark_pending(id).unwrap();
    assert_eq!(pool.request(id).unwrap().status, NtStatus::PENDING);
    assert_eq!(pool.request_cancel(id), Ok(true));
    assert_eq!(pool.request_cancel(id), Ok(false));
    pool.complete(id, NtStatus::from_u32(0xc000_0120), 0)
        .unwrap();
    assert!(matches!(
        pool.complete(id, NtStatus::SUCCESS, 0),
        Err(RequestError::InvalidState {
            state: RequestState::Completed
        })
    ));
    let completion = pool.reap(id).unwrap();
    assert!(completion.cancel_requested);
    assert_eq!(completion.status.as_u32(), 0xc000_0120);
}

#[test]
fn serialized_cancel_race_has_defined_winner_in_every_order() {
    let mut pool = RequestPool::<2>::try_new().unwrap();
    let before_pending = pool
        .allocate(DEVICE, MajorFunction::Read, 0, None, 0, 1)
        .unwrap();
    assert!(matches!(
        pool.request_cancel(before_pending),
        Err(RequestError::InvalidState {
            state: RequestState::Allocated,
        })
    ));
    assert_eq!(pool.release_unsubmitted(before_pending), Ok(()));

    let cancel_wins = pool
        .allocate(DEVICE, MajorFunction::Read, 0, None, 0, 1)
        .unwrap();
    pool.mark_dispatched(cancel_wins).unwrap();
    assert_eq!(pool.request_cancel(cancel_wins), Ok(true));
    assert_eq!(pool.mark_pending(cancel_wins), Ok(()));
    let request = pool.request(cancel_wins).unwrap();
    assert_eq!(request.state, RequestState::CancelRequested);
    assert_eq!(request.status, NtStatus::PENDING);
    assert!(matches!(
        pool.mark_pending(cancel_wins),
        Err(RequestError::InvalidState {
            state: RequestState::CancelRequested,
        })
    ));
    pool.complete(cancel_wins, NtStatus::SUCCESS, 1).unwrap();
    assert_eq!(pool.request_cancel(cancel_wins), Ok(false));
    assert!(pool.reap(cancel_wins).unwrap().cancel_requested);

    let completion_wins = pool
        .allocate(DEVICE, MajorFunction::Read, 0, None, 0, 1)
        .unwrap();
    pool.mark_dispatched(completion_wins).unwrap();
    pool.complete(completion_wins, NtStatus::SUCCESS, 1)
        .unwrap();
    assert_eq!(pool.request_cancel(completion_wins), Ok(false));
    assert!(!pool.reap(completion_wins).unwrap().cancel_requested);
}

#[test]
fn completion_byte_counts_are_checked_by_operation_direction() {
    let mut pool = RequestPool::<2>::try_new().unwrap();
    let read = pool
        .allocate(DEVICE, MajorFunction::Read, 0, None, 0, 8)
        .unwrap();
    pool.mark_dispatched(read).unwrap();
    assert_eq!(
        pool.complete(read, NtStatus::SUCCESS, 9),
        Err(RequestError::InvalidInformation {
            information: 9,
            maximum: 8
        })
    );

    let write = pool
        .allocate(DEVICE, MajorFunction::Write, 0, None, 7, 0)
        .unwrap();
    pool.mark_dispatched(write).unwrap();
    assert_eq!(
        pool.complete(write, NtStatus::SUCCESS, 8),
        Err(RequestError::InvalidInformation {
            information: 8,
            maximum: 7
        })
    );
}

#[test]
fn completion_rejects_pending_status_and_zero_information_violations() {
    let mut pool = RequestPool::<2>::try_new().unwrap();
    let read = pool
        .allocate(DEVICE, MajorFunction::Read, 0, None, 0, 1)
        .unwrap();
    pool.mark_dispatched(read).unwrap();
    assert_eq!(
        pool.complete(read, NtStatus::PENDING, 0),
        Err(RequestError::InvalidCompletionStatus)
    );
    assert_eq!(pool.request(read).unwrap().state, RequestState::Dispatched);

    let close = pool
        .allocate(DEVICE, MajorFunction::Close, 0, None, 10, 10)
        .unwrap();
    pool.mark_dispatched(close).unwrap();
    assert_eq!(
        pool.complete(close, NtStatus::SUCCESS, 1),
        Err(RequestError::InvalidInformation {
            information: 1,
            maximum: 0,
        })
    );
    assert_eq!(pool.request(close).unwrap().state, RequestState::Dispatched);
}

#[test]
fn create_and_pnp_information_follow_explicit_major_specific_policy() {
    let mut pool = RequestPool::<2>::try_new().unwrap();
    let create = pool
        .allocate(DEVICE, MajorFunction::Create, 0, None, 0, 0)
        .unwrap();
    pool.mark_dispatched(create).unwrap();
    assert_eq!(
        pool.complete(create, NtStatus::SUCCESS, 6),
        Err(RequestError::InvalidInformation {
            information: 6,
            maximum: 5,
        })
    );
    pool.complete(create, NtStatus::SUCCESS, 5).unwrap();
    assert_eq!(pool.reap(create).unwrap().information, 5);

    let pnp = pool
        .allocate(DEVICE, MajorFunction::Pnp, 0, None, 0, 0)
        .unwrap();
    pool.mark_dispatched(pnp).unwrap();
    pool.complete(pnp, NtStatus::SUCCESS, usize::MAX).unwrap();
    let completion = pool.reap(pnp).unwrap();
    assert_eq!(completion.major, MajorFunction::Pnp);
    assert_eq!(completion.information, usize::MAX);
}

#[test]
fn unsubmitted_rollback_and_stale_ids_are_safe() {
    let mut pool = RequestPool::<1>::try_new().unwrap();
    let old = pool
        .allocate(DEVICE, MajorFunction::Create, 0, None, 0, 0)
        .unwrap();
    pool.release_unsubmitted(old).unwrap();
    assert_eq!(pool.request(old), Err(RequestError::InvalidRequest));
    let new = pool
        .allocate(DEVICE, MajorFunction::Create, 0, None, 0, 0)
        .unwrap();
    assert_ne!(old, new);
    assert_eq!(
        pool.release_unsubmitted(RequestId::from_raw(u32::MAX)),
        Err(RequestError::InvalidRequest)
    );
}

#[test]
fn pool_full_never_partially_publishes() {
    let mut pool = RequestPool::<1>::try_new().unwrap();
    let first = pool
        .allocate(DEVICE, MajorFunction::Create, 0, None, 0, 0)
        .unwrap();
    assert_eq!(
        pool.allocate(DEVICE, MajorFunction::Close, 0, None, 0, 0),
        Err(RequestError::PoolFull)
    );
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.request(first).unwrap().major, MajorFunction::Create);
}

#[test]
fn exhaustive_short_action_sequences_preserve_pool_and_generation_invariants() {
    const ACTION_COUNT: usize = 7;
    const SEQUENCE_LENGTH: usize = 6;
    const SEQUENCE_COUNT: usize = 117_649;

    for encoded in 0..SEQUENCE_COUNT {
        let mut actions = encoded;
        let mut pool = RequestPool::<1>::try_new().unwrap();
        let mut current = None;
        let mut stale = [RequestId::NULL; SEQUENCE_LENGTH];
        let mut stale_len = 0usize;

        for _ in 0..SEQUENCE_LENGTH {
            let action = actions % ACTION_COUNT;
            actions /= ACTION_COUNT;
            let id = current.unwrap_or(RequestId::NULL);
            match action {
                0 => {
                    if let Ok(id) = pool.allocate(DEVICE, MajorFunction::Read, 0, None, 0, 1) {
                        assert!(current.is_none());
                        current = Some(id);
                    }
                },
                1 => {
                    let _succeeded = pool.mark_dispatched(id).is_ok();
                },
                2 => {
                    let _succeeded = pool.mark_pending(id).is_ok();
                },
                3 => {
                    let _outcome = pool.request_cancel(id);
                },
                4 => {
                    let _succeeded = pool.complete(id, NtStatus::SUCCESS, 0).is_ok();
                },
                5 => {
                    if pool.reap(id).is_ok() {
                        stale[stale_len] = id;
                        stale_len += 1;
                        current = None;
                    }
                },
                _ => {
                    if pool.release_unsubmitted(id).is_ok() {
                        stale[stale_len] = id;
                        stale_len += 1;
                        current = None;
                    }
                },
            }

            assert_eq!(pool.len(), usize::from(current.is_some()));
            if let Some(id) = current {
                assert!(pool.request(id).is_ok());
            }
            for id in &stale[..stale_len] {
                assert_eq!(pool.request(*id), Err(RequestError::InvalidRequest));
            }
        }
    }
}

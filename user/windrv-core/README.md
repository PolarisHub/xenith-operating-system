# Xenith Windows driver-host core

`xenith-windrv-core` is an allocation-free, safe-Rust policy core for a future
isolated Windows driver host. It provides bounded records and state machines;
it does not load or execute a Windows driver.

## Implemented policy

- Exact public `IRP_MJ_*` values and lossless 32-bit `CTL_CODE` packing and
  decoding. Function values wider than twelve bits are rejected.
- Low-half, overflow-checked driver image ranges and callback addresses.
- Independently generation-safe driver, device, request, and hardware-grant
  IDs. Exhausted generations retire their slots instead of wrapping.
- Linear device stacks with one upper edge per lower device, explicit cycle
  detection, and an exact eight-device depth limit.
- Explicit missing-dispatch errors; unsupported dispatch never reports fake
  success.
- A serialized request lifecycle covering allocate, dispatch, pending,
  cancellation request, completion, rollback, and reap. Completion rejects
  `STATUS_PENDING`, double completion, illegal states, oversized transfer
  descriptions, and out-of-range `IoStatus.Information` where the major has a
  modeled byte-count, zero, or create-disposition contract.
- Exactly attenuated I/O-port, MMIO, interrupt, and DMA-domain grant records.
  Empty/unknown rights and kind-invalid combinations are rejected. MMIO grants
  require `MAP` plus `READ` and/or `WRITE`.
- Operational inline bounds of 64 driver records, 255 device records, 1,024
  requests, and 255 hardware grants. Maximum accepted configurations are kept
  below audited 128-KiB per-object storage budgets.

## Exact limitations

- `IoMethod` and `IoAccess` only decode IOCTL bits. There is no Windows buffer
  manager, MDL construction/pinning, `METHOD_NEITHER` pointer validation, or
  file-handle access check. A future host must enforce those before dispatch.
- Cancellation transitions are deterministic only under the required external
  synchronization. This is not Windows cancel-spin-lock/cancel-routine
  emulation and does not itself resolve real concurrent driver callbacks.
- PnP `IoStatus.Information` is deliberately retained as an opaque,
  minor-function-specific value. It is tagged with the completed major and
  minor but is not pointer-validated by this core; the future PnP ABI adapter
  must do that.
- `RequestPool` validates only the syntax of a target `DeviceId`; the caller
  must validate liveness against the same `DriverRegistry` before publication.
- Callback validation proves only that an address is inside the supplied
  low-half image range. It does not prove executable page permissions or PE
  provenance.
- Hardware grants are policy data. This crate performs no port I/O, MMIO
  mapping, interrupt delivery/acknowledgement, DMA mapping, pinning, or IOMMU
  programming.
- There is no `.sys` loader, WDM structure ABI materialization, IRQL model,
  PnP/power manager, object namespace, security model, KMDF, or UMDF runtime.
- Storage is inline in const-generic values. A host should place large selected
  capacities in long-lived host state rather than transiently copying them on
  small worker stacks. Rust lays out a const-generic type before `try_new` can
  reject it, so callers must also avoid naming out-of-range capacities in
  untrusted-generated code; the runtime check cannot make such a type small.

General Windows-driver compatibility is not claimed. It requires an isolated
least-authority host, capability-scoped kernel services, ABI adapters, and
per-driver conformance tests.

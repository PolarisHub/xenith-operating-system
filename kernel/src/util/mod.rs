//! Shared kernel utilities: no-allocation container helpers.
//!
//! This module groups the small, heap-free data structures the kernel needs
//! before the slab allocator exists and that remain useful on hot paths even
//! after it does. Every type here borrows or embeds its storage — none of them
//! call `alloc` — so they are safe to use from early boot, from interrupt
//! handlers, and from per-CPU contexts where allocation is forbidden.
//!
//! # Contents
//!
//! * [`bitmap`] — [`Bitmap`]: a bit-level allocator view over a borrowed
//!   `&mut [u64]` word buffer. Backs the physical frame allocator and any
//!   fixed resource-set tracker (IRQ vectors, MSI slots, IO port bits).
//! * [`ringbuffer`] — [`RingBuffer`]: a single-producer/single-consumer
//!   bounded FIFO with a compile-time capacity. Backs early log buffering,
//!   keyboard input, and per-CPU event queues.
//! * [`linked_list`] — [`IntrusiveLinkedList`]: a doubly-linked list that
//!   threads through link storage on the elements themselves. Backs scheduler
//!   run queues, wait queues, and slab free lists.
//!
//! # Layering
//!
//! `util` is a leaf module: it depends only on `core` and on
//! [`crate::sync`] (by reference, for the documented locking wrapper around
//! cross-context ring buffer use). No other kernel subsystem depends on it
//! transitively except through these public types, so it is safe to build and
//! test in isolation.

pub mod bitmap;
pub mod linked_list;
pub mod ringbuffer;

// Flat re-exports so callers can write `crate::util::Bitmap` instead of
// drilling into the submodule. The submodule paths remain available for
// callers that prefer to scope imports explicitly.
pub use bitmap::Bitmap;
pub use linked_list::{IntrusiveLinkedList, Iter as LinkedIter, LinkEntry, Links};
pub use ringbuffer::RingBuffer;

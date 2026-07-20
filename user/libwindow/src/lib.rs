//! Allocation-free client library for Xenith's userspace compositor protocol.
//!
//! [`Client`] permits one outstanding request and accepts asynchronous events
//! while waiting for its correlated status reply. It keeps bounded local
//! surface and buffer state and performs all wire encoding and decoding without
//! casts, packed references, or serialization of Rust padding.

#![no_std]
#![forbid(unsafe_code)]

mod client;
mod transport;
mod wire;

pub use client::{
    ArgumentError, Client, Error, Event, EventKind, Incoming, ProtocolError, Reply, RequestKind,
    StateError, SurfaceInfo, MAX_TRACKED_BUFFERS, MAX_TRACKED_SURFACES,
};
pub use transport::{LibuserTransport, Transport};
pub use xenith_abi::compositor::{
    CompositorDamageRect, CompositorHandle, CompositorSurfaceMetadata,
};

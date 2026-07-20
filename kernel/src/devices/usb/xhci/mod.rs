//! xHCI host-controller implementation for bounded root-port boot HID.

pub mod context;
pub mod controller;
pub mod registers;
pub mod ring;
pub mod trb;
mod wait;

pub use controller::{is_xhci, ControllerError, XhciController, MAX_DEVICES};

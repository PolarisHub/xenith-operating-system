use xenith_abi::{IpcReceiveMessage, IpcSendMessage};

/// Message-preserving channel transport used by [`crate::Client`].
///
/// Implementations block until completion or the supplied Xenith IPC deadline;
/// the client never performs periodic nonblocking receive probes.
pub trait Transport {
    type Error;

    fn send(&mut self, message: &IpcSendMessage, timeout_ns: u64) -> Result<usize, Self::Error>;

    fn receive(
        &mut self,
        message: &mut IpcReceiveMessage,
        timeout_ns: u64,
    ) -> Result<usize, Self::Error>;

    /// Close one descriptor installed by a successful receive operation.
    ///
    /// Cleanup failures are deliberately not surfaced by [`crate::Client`]
    /// while it is reporting a protocol violation. Implementations must still
    /// attempt every requested close.
    fn close_descriptor(&mut self, descriptor: i32);
}

/// Xenith syscall-backed channel endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibuserTransport {
    endpoint: i32,
}

impl LibuserTransport {
    #[must_use]
    pub const fn new(endpoint: i32) -> Self {
        Self { endpoint }
    }

    #[must_use]
    pub const fn endpoint(&self) -> i32 {
        self.endpoint
    }

    #[must_use]
    pub const fn into_endpoint(self) -> i32 {
        self.endpoint
    }
}

impl Transport for LibuserTransport {
    type Error = libuser::Error;

    fn send(&mut self, message: &IpcSendMessage, timeout_ns: u64) -> Result<usize, Self::Error> {
        libuser::channel_send(self.endpoint, message, timeout_ns)
    }

    fn receive(
        &mut self,
        message: &mut IpcReceiveMessage,
        timeout_ns: u64,
    ) -> Result<usize, Self::Error> {
        libuser::channel_recv(self.endpoint, message, timeout_ns)
    }

    fn close_descriptor(&mut self, descriptor: i32) {
        let _ = libuser::syscall::close(descriptor);
    }
}

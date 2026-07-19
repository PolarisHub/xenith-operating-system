//! Anonymous byte pipes used by `pipe(2)` and shell pipelines.

extern crate alloc;

use alloc::sync::Arc;

use super::vfs::FsError;
use crate::sync::SpinLock;
use crate::util::ringbuffer::RingBuffer;

/// Pipe capacity and the maximum write Xenith guarantees to enqueue atomically.
pub const PIPE_CAPACITY: usize = 4096;
pub const PIPE_BUF: usize = PIPE_CAPACITY;

struct PipeState {
    bytes: RingBuffer<u8, PIPE_CAPACITY>,
    readers: usize,
    writers: usize,
}

impl PipeState {
    const fn new() -> Self {
        Self {
            bytes: RingBuffer::new(),
            readers: 1,
            writers: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeDirection {
    Read,
    Write,
}

/// One shared open description for either side of a pipe. Descriptor
/// duplication shares the enclosing `Arc<FileObject>`, so this object's drop
/// runs exactly once when the last duplicate (including fork copies) closes.
pub struct PipeEndpoint {
    state: Arc<SpinLock<PipeState>>,
    direction: PipeDirection,
}

impl PipeEndpoint {
    fn new(state: Arc<SpinLock<PipeState>>, direction: PipeDirection) -> Self {
        Self { state, direction }
    }

    #[must_use]
    pub const fn direction(&self) -> PipeDirection {
        self.direction
    }

    /// Blocking read. Empty pipes wait cooperatively while a writer remains;
    /// the last writer closing turns an empty read into EOF.
    pub fn read(&self, destination: &mut [u8], nonblocking: bool) -> Result<usize, FsError> {
        if self.direction != PipeDirection::Read {
            return Err(FsError::BadFileDescriptor);
        }
        if destination.is_empty() {
            return Ok(0);
        }
        loop {
            let mut state = self.state.lock();
            let mut read = 0;
            while read < destination.len() {
                let Some(byte) = state.bytes.pop() else {
                    break;
                };
                destination[read] = byte;
                read += 1;
            }
            if read != 0 {
                return Ok(read);
            }
            if state.writers == 0 {
                return Ok(0);
            }
            if nonblocking {
                return Err(FsError::WouldBlock);
            }
            drop(state);
            crate::sched::yield_now();
        }
    }

    /// Blocking write with atomic writes up to `PIPE_BUF`. When every reader
    /// has closed it fails with `BrokenPipe`; the syscall layer additionally
    /// queues SIGPIPE for the caller.
    pub fn write(&self, source: &[u8], nonblocking: bool) -> Result<usize, FsError> {
        if self.direction != PipeDirection::Write {
            return Err(FsError::BadFileDescriptor);
        }
        if source.is_empty() {
            return Ok(0);
        }

        let mut written = 0;
        while written < source.len() {
            let mut state = self.state.lock();
            if state.readers == 0 {
                return if written == 0 {
                    Err(FsError::BrokenPipe)
                } else {
                    Ok(written)
                };
            }
            let available = state.bytes.capacity() - state.bytes.len();
            let remaining = source.len() - written;
            let atomic = source.len() <= PIPE_BUF;
            if available == 0 || (atomic && available < remaining) {
                if nonblocking {
                    return if written == 0 {
                        Err(FsError::WouldBlock)
                    } else {
                        Ok(written)
                    };
                }
                drop(state);
                crate::sched::yield_now();
                continue;
            }
            let count = available.min(remaining);
            for &byte in &source[written..written + count] {
                // `count <= available`, so every push is guaranteed to fit.
                let _ = state.bytes.push(byte);
            }
            written += count;
        }
        Ok(written)
    }

    #[cfg(test)]
    fn buffered_len(&self) -> usize {
        self.state.lock().bytes.len()
    }
}

impl Drop for PipeEndpoint {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        match self.direction {
            PipeDirection::Read => state.readers = state.readers.saturating_sub(1),
            PipeDirection::Write => state.writers = state.writers.saturating_sub(1),
        }
    }
}

/// Create the read and write open descriptions for one anonymous pipe.
pub fn create() -> (PipeEndpoint, PipeEndpoint) {
    let state = Arc::new(SpinLock::new(PipeState::new()));
    (
        PipeEndpoint::new(Arc::clone(&state), PipeDirection::Read),
        PipeEndpoint::new(state, PipeDirection::Write),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_fifo_and_reads_may_be_short() {
        let (reader, writer) = create();
        assert_eq!(writer.write(b"abcdef", false).unwrap(), 6);
        assert_eq!(reader.buffered_len(), 6);
        let mut first = [0u8; 4];
        assert_eq!(reader.read(&mut first, false).unwrap(), 4);
        assert_eq!(&first, b"abcd");
        let mut second = [0u8; 4];
        assert_eq!(reader.read(&mut second, false).unwrap(), 2);
        assert_eq!(&second[..2], b"ef");
    }

    #[test]
    fn final_writer_close_produces_eof_after_buffer_drains() {
        let (reader, writer) = create();
        writer.write(b"x", false).unwrap();
        drop(writer);
        let mut byte = [0u8; 1];
        assert_eq!(reader.read(&mut byte, false).unwrap(), 1);
        assert_eq!(byte[0], b'x');
        assert_eq!(reader.read(&mut byte, false).unwrap(), 0);
    }

    #[test]
    fn final_reader_close_breaks_writes() {
        let (reader, writer) = create();
        drop(reader);
        assert_eq!(writer.write(b"x", false), Err(FsError::BrokenPipe));
    }

    #[test]
    fn nonblocking_empty_and_full_return_would_block() {
        let (reader, writer) = create();
        let mut byte = [0u8; 1];
        assert_eq!(reader.read(&mut byte, true), Err(FsError::WouldBlock));
        let full = [b'x'; PIPE_CAPACITY];
        assert_eq!(writer.write(&full, false).unwrap(), PIPE_CAPACITY);
        assert_eq!(writer.write(b"y", true), Err(FsError::WouldBlock));
    }
}

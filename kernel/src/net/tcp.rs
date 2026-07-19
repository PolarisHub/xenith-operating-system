//! TCP segment validation and a bounded RFC 793-style connection state machine.

use core::fmt;

use super::ip::{add_ipv4_pseudo_header, Checksum, IpProtocol, Ipv4Addr};
use super::PacketError;

pub const MIN_HEADER_LEN: usize = 20;
pub const MAX_HEADER_LEN: usize = 60;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    pub const FIN: Self = Self(1 << 0);
    pub const SYN: Self = Self(1 << 1);
    pub const RST: Self = Self(1 << 2);
    pub const PSH: Self = Self(1 << 3);
    pub const ACK: Self = Self(1 << 4);
    pub const URG: Self = Self(1 << 5);
    pub const ECE: Self = Self(1 << 6);
    pub const CWR: Self = Self(1 << 7);
    pub const NS: Self = Self(1 << 8);

    #[must_use]
    pub const fn from_bits_truncate(bits: u16) -> Self {
        Self(bits & 0x01ff)
    }

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Debug for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (Self::FIN, "FIN"),
            (Self::SYN, "SYN"),
            (Self::RST, "RST"),
            (Self::PSH, "PSH"),
            (Self::ACK, "ACK"),
            (Self::URG, "URG"),
            (Self::ECE, "ECE"),
            (Self::CWR, "CWR"),
            (Self::NS, "NS"),
        ];
        let mut first = true;
        for (flag, name) in names {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("NONE")
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < MIN_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        let header_len = usize::from(bytes[12] >> 4) * 4;
        if !(MIN_HEADER_LEN..=MAX_HEADER_LEN).contains(&header_len) || header_len > bytes.len() {
            return Err(PacketError::Malformed);
        }
        let ns = u16::from(bytes[12] & 1) << 8;
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            sequence: u32::from_be_bytes(bytes[4..8].try_into().expect("four-byte slice")),
            acknowledgement: u32::from_be_bytes(bytes[8..12].try_into().expect("four-byte slice")),
            flags: TcpFlags::from_bits_truncate(ns | u16::from(bytes[13])),
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            urgent_pointer: u16::from_be_bytes([bytes[18], bytes[19]]),
            options: &bytes[MIN_HEADER_LEN..header_len],
            payload: &bytes[header_len..],
        })
    }

    pub fn parse_ipv4(
        bytes: &'a [u8],
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<Self, PacketError> {
        let segment = Self::parse(bytes)?;
        let length = u16::try_from(bytes.len()).map_err(|_| PacketError::Oversized)?;
        let mut checksum = Checksum::new();
        add_ipv4_pseudo_header(&mut checksum, source, destination, IpProtocol::Tcp, length);
        checksum.add(bytes);
        if checksum.finish() != 0 {
            return Err(PacketError::BadChecksum);
        }
        Ok(segment)
    }

    #[must_use]
    pub fn sequence_len(&self) -> u32 {
        let control = u32::from(self.flags.contains(TcpFlags::SYN))
            + u32::from(self.flags.contains(TcpFlags::FIN));
        u32::try_from(self.payload.len())
            .unwrap_or(u32::MAX)
            .saturating_add(control)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub fn write_ipv4(
        self,
        output: &mut [u8],
        source: Ipv4Addr,
        destination: Ipv4Addr,
        options: &[u8],
        payload: &[u8],
    ) -> Result<usize, PacketError> {
        if options.len() > 40 || !options.len().is_multiple_of(4) {
            return Err(PacketError::Malformed);
        }
        let header_len = MIN_HEADER_LEN + options.len();
        let length = header_len
            .checked_add(payload.len())
            .ok_or(PacketError::Oversized)?;
        let length_u16 = u16::try_from(length).map_err(|_| PacketError::Oversized)?;
        if output.len() < length {
            return Err(PacketError::BufferTooSmall);
        }
        output[..length].fill(0);
        output[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        output[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        output[4..8].copy_from_slice(&self.sequence.to_be_bytes());
        output[8..12].copy_from_slice(&self.acknowledgement.to_be_bytes());
        output[12] = ((header_len / 4) as u8) << 4;
        if self.flags.contains(TcpFlags::NS) {
            output[12] |= 1;
        }
        output[13] = self.flags.bits() as u8;
        output[14..16].copy_from_slice(&self.window.to_be_bytes());
        output[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        output[MIN_HEADER_LEN..header_len].copy_from_slice(options);
        output[header_len..length].copy_from_slice(payload);
        let mut checksum = Checksum::new();
        add_ipv4_pseudo_header(
            &mut checksum,
            source,
            destination,
            IpProtocol::Tcp,
            length_u16,
        );
        checksum.add(&output[..length]);
        output[16..18].copy_from_slice(&checksum.finish().to_be_bytes());
        Ok(length)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpReply {
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: TcpFlags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpAction {
    None,
    Send(TcpReply),
    Connected(Option<TcpReply>),
    Deliver {
        length: usize,
        reply: Option<TcpReply>,
    },
    PeerClosed(TcpReply),
    Closed,
    Reset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpStateError {
    InvalidState,
    InvalidAcknowledgement,
    UnacceptableSequence,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpControlBlock {
    pub state: TcpState,
    pub iss: u32,
    pub irs: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub snd_wnd: u16,
    pub rcv_wnd: u16,
}

impl TcpControlBlock {
    #[must_use]
    pub const fn closed(receive_window: u16) -> Self {
        Self {
            state: TcpState::Closed,
            iss: 0,
            irs: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            snd_wnd: 0,
            rcv_wnd: receive_window,
        }
    }

    pub fn listen(&mut self, initial_sequence: u32) -> Result<(), TcpStateError> {
        if self.state != TcpState::Closed {
            return Err(TcpStateError::InvalidState);
        }
        self.iss = initial_sequence;
        self.snd_una = initial_sequence;
        self.snd_nxt = initial_sequence;
        self.state = TcpState::Listen;
        Ok(())
    }

    pub fn connect(&mut self, initial_sequence: u32) -> Result<TcpReply, TcpStateError> {
        if self.state != TcpState::Closed {
            return Err(TcpStateError::InvalidState);
        }
        self.iss = initial_sequence;
        self.snd_una = initial_sequence;
        self.snd_nxt = initial_sequence.wrapping_add(1);
        self.state = TcpState::SynSent;
        Ok(TcpReply {
            sequence: initial_sequence,
            acknowledgement: 0,
            flags: TcpFlags::SYN,
        })
    }

    pub fn close(&mut self) -> Result<TcpReply, TcpStateError> {
        let next = match self.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return Err(TcpStateError::InvalidState),
        };
        let reply = TcpReply {
            sequence: self.snd_nxt,
            acknowledgement: self.rcv_nxt,
            flags: TcpFlags::FIN.union(TcpFlags::ACK),
        };
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = next;
        Ok(reply)
    }

    #[must_use]
    fn ack_reply(&self) -> TcpReply {
        TcpReply {
            sequence: self.snd_nxt,
            acknowledgement: self.rcv_nxt,
            flags: TcpFlags::ACK,
        }
    }

    fn segment_acceptable(&self, segment: &TcpSegment<'_>) -> bool {
        let length = segment.sequence_len();
        if self.rcv_wnd == 0 {
            return length == 0 && segment.sequence == self.rcv_nxt;
        }
        if length == 0 {
            return seq_in_window(segment.sequence, self.rcv_nxt, self.rcv_wnd);
        }
        seq_in_window(segment.sequence, self.rcv_nxt, self.rcv_wnd)
            || seq_in_window(
                segment.sequence.wrapping_add(length - 1),
                self.rcv_nxt,
                self.rcv_wnd,
            )
    }

    pub fn on_segment(&mut self, segment: &TcpSegment<'_>) -> Result<TcpAction, TcpStateError> {
        match self.state {
            TcpState::Closed => {
                if segment.flags.contains(TcpFlags::RST) {
                    return Ok(TcpAction::None);
                }
                let reply = if segment.flags.contains(TcpFlags::ACK) {
                    TcpReply {
                        sequence: segment.acknowledgement,
                        acknowledgement: 0,
                        flags: TcpFlags::RST,
                    }
                } else {
                    TcpReply {
                        sequence: 0,
                        acknowledgement: segment.sequence.wrapping_add(segment.sequence_len()),
                        flags: TcpFlags::RST.union(TcpFlags::ACK),
                    }
                };
                return Ok(TcpAction::Send(reply));
            },
            TcpState::Listen => return self.on_listen_segment(segment),
            TcpState::SynSent => return self.on_syn_sent_segment(segment),
            _ => {},
        }

        if !self.segment_acceptable(segment) {
            return Ok(if segment.flags.contains(TcpFlags::RST) {
                TcpAction::None
            } else {
                TcpAction::Send(self.ack_reply())
            });
        }
        if segment.flags.contains(TcpFlags::RST) {
            self.state = TcpState::Closed;
            return Ok(TcpAction::Reset);
        }
        if segment.flags.contains(TcpFlags::SYN) {
            self.state = TcpState::Closed;
            return Ok(TcpAction::Reset);
        }
        if !segment.flags.contains(TcpFlags::ACK) {
            return Ok(TcpAction::None);
        }
        if seq_after(segment.acknowledgement, self.snd_nxt) {
            return Err(TcpStateError::InvalidAcknowledgement);
        }
        if seq_after(segment.acknowledgement, self.snd_una) {
            self.snd_una = segment.acknowledgement;
        }
        self.snd_wnd = segment.window;

        if self.state == TcpState::SynReceived {
            if segment.acknowledgement != self.snd_nxt {
                return Err(TcpStateError::InvalidAcknowledgement);
            }
            self.state = TcpState::Established;
            if segment.payload.is_empty() && !segment.flags.contains(TcpFlags::FIN) {
                return Ok(TcpAction::Connected(None));
            }
        }
        if self.state == TcpState::FinWait1 && segment.acknowledgement == self.snd_nxt {
            self.state = TcpState::FinWait2;
        } else if self.state == TcpState::Closing && segment.acknowledgement == self.snd_nxt {
            self.state = TcpState::TimeWait;
            return Ok(TcpAction::Closed);
        } else if self.state == TcpState::LastAck && segment.acknowledgement == self.snd_nxt {
            self.state = TcpState::Closed;
            return Ok(TcpAction::Closed);
        }

        if segment.sequence != self.rcv_nxt
            && (!segment.payload.is_empty() || segment.flags.contains(TcpFlags::FIN))
        {
            return Ok(TcpAction::Send(self.ack_reply()));
        }

        let delivered = segment.payload.len();
        self.rcv_nxt = self
            .rcv_nxt
            .wrapping_add(u32::try_from(delivered).unwrap_or(u32::MAX));
        if segment.flags.contains(TcpFlags::FIN) {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = match self.state {
                TcpState::Established | TcpState::SynReceived => TcpState::CloseWait,
                TcpState::FinWait1 => TcpState::Closing,
                TcpState::FinWait2 => TcpState::TimeWait,
                state => state,
            };
            return Ok(TcpAction::PeerClosed(self.ack_reply()));
        }
        if delivered != 0 {
            return Ok(TcpAction::Deliver {
                length: delivered,
                reply: Some(self.ack_reply()),
            });
        }
        Ok(TcpAction::None)
    }

    fn on_listen_segment(&mut self, segment: &TcpSegment<'_>) -> Result<TcpAction, TcpStateError> {
        if segment.flags.contains(TcpFlags::RST) {
            return Ok(TcpAction::None);
        }
        if segment.flags.contains(TcpFlags::ACK) {
            return Ok(TcpAction::Send(TcpReply {
                sequence: segment.acknowledgement,
                acknowledgement: 0,
                flags: TcpFlags::RST,
            }));
        }
        if !segment.flags.contains(TcpFlags::SYN) {
            return Ok(TcpAction::None);
        }
        self.irs = segment.sequence;
        self.rcv_nxt = segment.sequence.wrapping_add(1);
        self.snd_una = self.iss;
        self.snd_nxt = self.iss.wrapping_add(1);
        self.snd_wnd = segment.window;
        self.state = TcpState::SynReceived;
        Ok(TcpAction::Send(TcpReply {
            sequence: self.iss,
            acknowledgement: self.rcv_nxt,
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
        }))
    }

    fn on_syn_sent_segment(
        &mut self,
        segment: &TcpSegment<'_>,
    ) -> Result<TcpAction, TcpStateError> {
        let ack = segment.flags.contains(TcpFlags::ACK);
        if ack
            && (seq_before_eq(segment.acknowledgement, self.iss)
                || seq_after(segment.acknowledgement, self.snd_nxt))
        {
            if segment.flags.contains(TcpFlags::RST) {
                return Ok(TcpAction::None);
            }
            return Ok(TcpAction::Send(TcpReply {
                sequence: segment.acknowledgement,
                acknowledgement: 0,
                flags: TcpFlags::RST,
            }));
        }
        if segment.flags.contains(TcpFlags::RST) {
            if ack {
                self.state = TcpState::Closed;
                return Ok(TcpAction::Reset);
            }
            return Ok(TcpAction::None);
        }
        if !segment.flags.contains(TcpFlags::SYN) {
            return Ok(TcpAction::None);
        }
        self.irs = segment.sequence;
        self.rcv_nxt = segment.sequence.wrapping_add(1);
        self.snd_wnd = segment.window;
        if ack {
            self.snd_una = segment.acknowledgement;
        }
        if ack && seq_after(self.snd_una, self.iss) {
            self.state = TcpState::Established;
            Ok(TcpAction::Connected(Some(self.ack_reply())))
        } else {
            self.state = TcpState::SynReceived;
            Ok(TcpAction::Send(TcpReply {
                sequence: self.iss,
                acknowledgement: self.rcv_nxt,
                flags: TcpFlags::SYN.union(TcpFlags::ACK),
            }))
        }
    }
}

#[inline]
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
fn seq_before_eq(a: u32, b: u32) -> bool {
    a == b || seq_before(a, b)
}

#[inline]
fn seq_after(a: u32, b: u32) -> bool {
    seq_before(b, a)
}

#[inline]
fn seq_in_window(sequence: u32, start: u32, window: u16) -> bool {
    !seq_before(sequence, start) && seq_before(sequence, start.wrapping_add(u32::from(window)))
}

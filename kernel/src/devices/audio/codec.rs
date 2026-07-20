//! HDA codec command encoding and bounded discovery records.

/// Codec address 15 is reserved by the link protocol, so usable addresses
/// are zero through fourteen even though the verb field is four bits wide.
pub const MAX_CODEC_ADDRESS: u8 = 0x0e;
/// STATESTS exposes presence bits for codec addresses 0 through 14.
pub const DISCOVERABLE_CODECS: usize = 15;
/// Upper bound retained from a codec's subordinate-node report.
pub const MAX_FUNCTION_GROUPS: usize = 32;

pub const PARAM_VENDOR_ID: u8 = 0x00;
pub const PARAM_REVISION_ID: u8 = 0x02;
pub const PARAM_SUBORDINATE_NODE_COUNT: u8 = 0x04;
pub const PARAM_FUNCTION_GROUP_TYPE: u8 = 0x05;
pub const VERB_GET_PARAMETER: u16 = 0x0f00;

/// A validated 32-bit codec command as placed in a CORB entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Verb(u32);

impl Verb {
    /// Construct a 12-bit verb with an 8-bit payload.
    #[must_use]
    pub const fn new(codec: u8, node: u8, verb: u16, payload: u8) -> Option<Self> {
        if codec > MAX_CODEC_ADDRESS || verb > 0x0fff {
            return None;
        }
        Some(Self(
            ((codec as u32) << 28) | ((node as u32) << 20) | ((verb as u32) << 8) | payload as u32,
        ))
    }

    #[must_use]
    pub const fn get_parameter(codec: u8, node: u8, parameter: u8) -> Option<Self> {
        Self::new(codec, node, VERB_GET_PARAMETER, parameter)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn codec(self) -> u8 {
        (self.0 >> 28) as u8
    }

    #[must_use]
    pub const fn node(self) -> u8 {
        ((self.0 >> 20) & 0xff) as u8
    }
}

/// One function group advertised beneath a codec's root node.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FunctionGroupInfo {
    pub node_id: u8,
    /// Low byte of the Function Group Type parameter (1 = audio, 2 = modem).
    pub group_type: u8,
    pub unsolicited_capable: bool,
}

/// Bounded discovery snapshot for a codec present at one SDI address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecInfo {
    pub address: u8,
    pub vendor_device_id: u32,
    pub revision_id: u32,
    groups: [FunctionGroupInfo; MAX_FUNCTION_GROUPS],
    group_count: u8,
    /// True when the codec advertised more groups than the fixed snapshot can
    /// retain. Discovery remains safe and reports the truncation explicitly.
    pub groups_truncated: bool,
}

impl CodecInfo {
    #[must_use]
    pub const fn new(address: u8, vendor_device_id: u32, revision_id: u32) -> Self {
        Self {
            address,
            vendor_device_id,
            revision_id,
            groups: [FunctionGroupInfo {
                node_id: 0,
                group_type: 0,
                unsolicited_capable: false,
            }; MAX_FUNCTION_GROUPS],
            group_count: 0,
            groups_truncated: false,
        }
    }

    pub(crate) fn push_group(&mut self, group: FunctionGroupInfo) {
        let index = self.group_count as usize;
        if index < self.groups.len() {
            self.groups[index] = group;
            self.group_count += 1;
        } else {
            self.groups_truncated = true;
        }
    }

    #[must_use]
    pub fn function_groups(&self) -> &[FunctionGroupInfo] {
        &self.groups[..self.group_count as usize]
    }

    #[must_use]
    pub fn audio_function_group_count(&self) -> usize {
        self.function_groups()
            .iter()
            .filter(|group| group.group_type == 0x01)
            .count()
    }
}

/// Decode Parameter 04h (starting node in bits 23:16, count in bits 7:0).
#[must_use]
pub const fn subordinate_nodes(response: u32) -> (u8, u8) {
    (((response >> 16) & 0xff) as u8, (response & 0xff) as u8)
}

/// Decode the fields needed from Parameter 05h.
#[must_use]
pub const fn function_group(node_id: u8, response: u32) -> FunctionGroupInfo {
    FunctionGroupInfo {
        node_id,
        group_type: (response & 0xff) as u8,
        unsolicited_capable: response & (1 << 8) != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_encoding_preserves_codec_node_opcode_and_payload() {
        let verb = Verb::get_parameter(3, 0x17, PARAM_FUNCTION_GROUP_TYPE).unwrap();
        assert_eq!(verb.raw(), 0x317f_0005);
        assert_eq!(verb.codec(), 3);
        assert_eq!(verb.node(), 0x17);
        assert!(Verb::new(15, 0, 0, 0).is_none());
        assert!(Verb::new(0, 0, 0x1000, 0).is_none());
    }

    #[test]
    fn subordinate_node_parameter_is_split_without_sign_extension() {
        assert_eq!(subordinate_nodes(0x0034_00a2), (0x34, 0xa2));
    }

    #[test]
    fn codec_snapshot_is_bounded_and_reports_truncation() {
        let mut info = CodecInfo::new(0, 0x10ec_0892, 0x0010_0300);
        for node in 0..(MAX_FUNCTION_GROUPS + 3) {
            info.push_group(function_group(node as u8, 0x101));
        }
        assert_eq!(info.function_groups().len(), MAX_FUNCTION_GROUPS);
        assert_eq!(info.audio_function_group_count(), MAX_FUNCTION_GROUPS);
        assert!(info.groups_truncated);
    }
}

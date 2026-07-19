//! Checksums shared by the host image builder and the on-disk manifest.

const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Computes the FNV-1a 64-bit checksum used by the Xenith disk manifest.
///
/// FNV-1a is intentionally used here because a 16-bit boot stage can implement
/// it in a few instructions without needing a table or a crypto library. The
/// checksum detects corrupt build artifacts; it is not an authenticity proof.
#[must_use]
pub fn payload_checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV1A_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV1A_PRIME)
    })
}

#[cfg(test)]
mod tests {
    use super::payload_checksum;

    #[test]
    fn fnv1a_matches_published_vectors() {
        assert_eq!(payload_checksum(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(payload_checksum(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(payload_checksum(b"foobar"), 0x8594_4171_f739_67e8);
    }
}

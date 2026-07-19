//! Checksums used by the raw image container.

/// FNV-1a 64-bit offset basis.
pub const FNV1A64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV1A64_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

/// Hash a byte string while treating one field as all-zero.
#[must_use]
pub fn fnv1a64_with_zeroed_range(bytes: &[u8], zero_start: usize, zero_len: usize) -> u64 {
    let zero_end = zero_start.saturating_add(zero_len);
    let mut hash = FNV1A64_OFFSET_BASIS;
    for (index, &byte) in bytes.iter().enumerate() {
        hash ^= if index >= zero_start && index < zero_end {
            0
        } else {
            u64::from(byte)
        };
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_published_fnv_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn zeroed_field_matches_an_explicit_copy() {
        let input = *b"abcdefghijklmnop";
        let mut expected = input;
        expected[4..10].fill(0);
        assert_eq!(fnv1a64_with_zeroed_range(&input, 4, 6), fnv1a64(&expected));
    }
}

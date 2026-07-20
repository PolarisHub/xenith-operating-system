//! Bounded normalization for the initial NT object-path subset.

const DOS_PREFIX: &[u16] = &[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];
const DEVICE_PREFIX: &[u16] = &[
    b'\\' as u16,
    b'D' as u16,
    b'E' as u16,
    b'V' as u16,
    b'I' as u16,
    b'C' as u16,
    b'E' as u16,
    b'\\' as u16,
];

/// Namespace recognized by the bootstrap normalizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtPathKind {
    /// DOS-device namespace beginning with `\??\`.
    DosDevices,
    /// Native device namespace beginning with `\Device\`.
    Device,
    /// A name relative to a caller-supplied object-directory handle.
    Relative,
}

/// Path normalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    /// No UTF-16 units were supplied.
    Empty,
    /// An absolute namespace other than `\??\` or `\Device\` was supplied.
    UnsupportedAbsoluteNamespace,
    /// The namespace prefix had no following object name.
    MissingObjectName,
    /// A parent component would escape the selected namespace root.
    ParentEscapesRoot,
    /// An embedded UTF-16 NUL was found.
    EmbeddedNul {
        /// Input code-unit index.
        index: usize,
    },
    /// A lone or incorrectly paired UTF-16 surrogate was found.
    InvalidUtf16 {
        /// Input code-unit index.
        index: usize,
    },
    /// A control character or forward slash was found.
    InvalidCharacter {
        /// Input code-unit index.
        index: usize,
        /// Rejected UTF-16 code unit.
        unit: u16,
    },
    /// The normalized path exceeds the output's const-generic capacity.
    BufferTooSmall {
        /// Output capacity in UTF-16 code units.
        capacity: usize,
    },
}

/// Canonical, fixed-capacity UTF-16 NT path.
///
/// Basic Latin letters are folded to uppercase, making namespace and ordinary
/// ASCII components case-insensitive. Well-formed non-ASCII UTF-16 is retained
/// byte-for-byte and therefore compared ordinally in this bootstrap subset; no
/// locale or Unicode-table behavior is guessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedNtPath<const N: usize> {
    units: [u16; N],
    len: usize,
    kind: NtPathKind,
}

impl<const N: usize> NormalizedNtPath<N> {
    /// Returns the canonical UTF-16 code units without a trailing NUL.
    #[must_use]
    pub fn as_units(&self) -> &[u16] {
        &self.units[..self.len]
    }

    /// Returns the canonical length in UTF-16 code units.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether this canonical path is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the recognized namespace.
    #[must_use]
    pub const fn kind(&self) -> NtPathKind {
        self.kind
    }
}

/// Normalizes the supported NT path subset without allocating.
///
/// Repeated separators and `.` are removed, `..` is resolved without allowing
/// namespace escape, and ASCII letters are folded to uppercase. Forward slashes,
/// controls, embedded NULs, malformed UTF-16, and other absolute namespaces are
/// rejected. At least one object-name component is required after a prefix.
pub fn normalize_nt_path<const N: usize>(input: &[u16]) -> Result<NormalizedNtPath<N>, PathError> {
    if input.is_empty() {
        return Err(PathError::Empty);
    }

    let (kind, mut cursor, prefix): (NtPathKind, usize, &[u16]) =
        if starts_with_ascii_case_insensitive(input, DOS_PREFIX) {
            (NtPathKind::DosDevices, DOS_PREFIX.len(), DOS_PREFIX)
        } else if starts_with_ascii_case_insensitive(input, DEVICE_PREFIX) {
            (NtPathKind::Device, DEVICE_PREFIX.len(), DEVICE_PREFIX)
        } else if input[0] == b'\\' as u16 {
            return Err(PathError::UnsupportedAbsoluteNamespace);
        } else {
            (NtPathKind::Relative, 0, &[])
        };

    let mut output = NormalizedNtPath {
        units: [0; N],
        len: 0,
        kind,
    };
    for unit in prefix.iter().copied() {
        push(&mut output, unit)?;
    }

    // At most N nonempty components can fit in an N-code-unit result.
    let mut rewind_points = [0_usize; N];
    let mut component_count = 0_usize;

    while cursor < input.len() {
        while cursor < input.len() && input[cursor] == b'\\' as u16 {
            cursor += 1;
        }
        if cursor == input.len() {
            break;
        }
        let start = cursor;
        while cursor < input.len() && input[cursor] != b'\\' as u16 {
            cursor += 1;
        }
        let component = &input[start..cursor];

        if component == [b'.' as u16] {
            continue;
        }
        if component == [b'.' as u16, b'.' as u16] {
            if component_count == 0 {
                return Err(PathError::ParentEscapesRoot);
            }
            component_count -= 1;
            let new_len = rewind_points[component_count];
            for unit in &mut output.units[new_len..output.len] {
                *unit = 0;
            }
            output.len = new_len;
            continue;
        }

        validate_component(component, start)?;
        let rewind = output.len;
        if component_count != 0 && !ends_with_separator(&output) {
            push(&mut output, b'\\' as u16)?;
        }
        if component_count >= rewind_points.len() {
            return Err(PathError::BufferTooSmall { capacity: N });
        }
        rewind_points[component_count] = rewind;
        for unit in component.iter().copied() {
            push(&mut output, ascii_upper(unit))?;
        }
        component_count += 1;
    }

    if component_count == 0 {
        return Err(PathError::MissingObjectName);
    }
    Ok(output)
}

fn push<const N: usize>(path: &mut NormalizedNtPath<N>, unit: u16) -> Result<(), PathError> {
    if path.len == N {
        return Err(PathError::BufferTooSmall { capacity: N });
    }
    path.units[path.len] = unit;
    path.len += 1;
    Ok(())
}

fn ends_with_separator<const N: usize>(path: &NormalizedNtPath<N>) -> bool {
    path.len != 0 && path.units[path.len - 1] == b'\\' as u16
}

fn starts_with_ascii_case_insensitive(input: &[u16], expected: &[u16]) -> bool {
    input.len() >= expected.len()
        && input[..expected.len()]
            .iter()
            .copied()
            .zip(expected.iter().copied())
            .all(|(left, right)| ascii_upper(left) == ascii_upper(right))
}

const fn ascii_upper(unit: u16) -> u16 {
    if unit >= b'a' as u16 && unit <= b'z' as u16 {
        unit - (b'a' - b'A') as u16
    } else {
        unit
    }
}

fn validate_component(component: &[u16], input_start: usize) -> Result<(), PathError> {
    let mut index = 0_usize;
    while index < component.len() {
        let unit = component[index];
        if unit == 0 {
            return Err(PathError::EmbeddedNul {
                index: input_start + index,
            });
        }
        if unit < 0x20 || unit == b'/' as u16 {
            return Err(PathError::InvalidCharacter {
                index: input_start + index,
                unit,
            });
        }
        if (0xd800..=0xdbff).contains(&unit) {
            if index + 1 == component.len() || !(0xdc00..=0xdfff).contains(&component[index + 1]) {
                return Err(PathError::InvalidUtf16 {
                    index: input_start + index,
                });
            }
            index += 2;
            continue;
        }
        if (0xdc00..=0xdfff).contains(&unit) {
            return Err(PathError::InvalidUtf16 {
                index: input_start + index,
            });
        }
        index += 1;
    }
    Ok(())
}

//! Owned DWARF line-table index used by the interactive debugger.
//!
//! `addr2line` and `gimli` do the format parsing.  The loader's borrowed
//! results are copied into a compact, path/line index so command translation
//! does not keep an ELF file mapped and reverse `file:line` lookups stay
//! deterministic.

use std::collections::BTreeSet;
use std::path::Path;
use std::{fmt, io};

use addr2line::Loader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.file, self.line)?;
        if let Some(column) = self.column.filter(|column| *column != 0) {
            write!(formatter, ":{column}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRange {
    pub start: u64,
    pub end: u64,
    pub location: SourceLocation,
}

impl SourceRange {
    #[must_use]
    pub const fn contains(&self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
}

#[derive(Clone, Debug, Default)]
pub struct SourceMap {
    ranges: Vec<SourceRange>,
    files: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceLookupError {
    Invalid(String),
    NotFound(String),
    Ambiguous { spec: String, files: Vec<String> },
}

impl fmt::Display for SourceLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(spec) => write!(formatter, "invalid source location {spec}"),
            Self::NotFound(spec) => write!(formatter, "no executable code for {spec}"),
            Self::Ambiguous { spec, files } => {
                write!(formatter, "ambiguous source location {spec} (matches ")?;
                for (index, file) in files.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }
                    formatter.write_str(file)?;
                }
                formatter.write_str(")")
            },
        }
    }
}

impl std::error::Error for SourceLookupError {}

impl SourceMap {
    #[must_use]
    pub fn from_ranges(ranges: impl IntoIterator<Item = SourceRange>) -> Self {
        let mut ranges: Vec<_> = ranges
            .into_iter()
            .filter(|range| range.start < range.end && range.location.line != 0)
            .collect();
        ranges.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then_with(|| left.end.cmp(&right.end))
                .then_with(|| left.location.file.cmp(&right.location.file))
                .then_with(|| left.location.line.cmp(&right.location.line))
        });
        ranges.dedup();
        let files = ranges
            .iter()
            .map(|range| range.location.file.clone())
            .collect();
        Self { ranges, files }
    }

    pub(crate) fn load(path: &Path) -> Result<Self, io::Error> {
        let loader = Loader::new(path).map_err(dwarf_io_error)?;
        let has_info = loader.get_section_range(b".debug_info").is_some();
        let has_lines = loader.get_section_range(b".debug_line").is_some();
        if !has_info && !has_lines {
            return Ok(Self::default());
        }
        if !has_info || !has_lines {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF has an incomplete DWARF line-table section set",
            ));
        }

        let iter = loader
            .find_location_range(0, u64::MAX)
            .map_err(dwarf_io_error)?;
        let ranges = iter.filter_map(|(start, length, location)| {
            let end = start.checked_add(length)?;
            let file = location.file?.to_owned();
            let line = location.line.filter(|line| *line != 0)?;
            Some(SourceRange {
                start,
                end,
                location: SourceLocation {
                    file,
                    line,
                    column: location.column,
                },
            })
        });
        Ok(Self::from_ranges(ranges))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(String::as_str)
    }

    #[must_use]
    pub fn lookup(&self, address: u64) -> Option<&SourceLocation> {
        let end = self.ranges.partition_point(|range| range.start <= address);
        self.ranges[..end]
            .iter()
            .rev()
            .find(|range| range.contains(address))
            .map(|range| &range.location)
    }

    pub fn resolve(&self, spec: &str) -> Result<Option<u64>, SourceLookupError> {
        let Some(parsed) = parse_source_spec(spec)? else {
            return Ok(None);
        };
        if self.is_empty() {
            return Err(SourceLookupError::NotFound(spec.to_owned()));
        }

        let mut candidates = Vec::new();
        let mut best_rank = 0;
        for range in &self.ranges {
            if range.location.line != parsed.line
                || parsed
                    .column
                    .is_some_and(|column| range.location.column != Some(column))
            {
                continue;
            }
            let Some(rank) = file_match_rank(&range.location.file, parsed.file) else {
                continue;
            };
            if rank > best_rank {
                best_rank = rank;
                candidates.clear();
            }
            if rank == best_rank {
                candidates.push(range);
            }
        }
        if candidates.is_empty() {
            return Err(SourceLookupError::NotFound(spec.to_owned()));
        }

        let files: BTreeSet<_> = candidates
            .iter()
            .map(|range| range.location.file.clone())
            .collect();
        if files.len() > 1 {
            return Err(SourceLookupError::Ambiguous {
                spec: spec.to_owned(),
                files: files.into_iter().collect(),
            });
        }
        Ok(candidates.iter().map(|range| range.start).min())
    }

    pub(crate) fn apply_load_bias(&mut self, bias: u64) -> Result<(), ()> {
        if bias == 0 {
            return Ok(());
        }
        if self.ranges.iter().any(|range| {
            range.start.checked_add(bias).is_none() || range.end.checked_add(bias).is_none()
        }) {
            return Err(());
        }
        for range in &mut self.ranges {
            range.start += bias;
            range.end += bias;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedSourceSpec<'a> {
    file: &'a str,
    line: u32,
    column: Option<u32>,
}

fn parse_source_spec(spec: &str) -> Result<Option<ParsedSourceSpec<'_>>, SourceLookupError> {
    let Some((prefix, last)) = spec.rsplit_once(':') else {
        return Ok(None);
    };
    let Ok(last) = last.parse::<u32>() else {
        return Ok(None);
    };
    let (file, line, column) = match prefix.rsplit_once(':') {
        Some((file, line)) if line.bytes().all(|byte| byte.is_ascii_digit()) => {
            let line = line
                .parse::<u32>()
                .map_err(|_| SourceLookupError::Invalid(spec.to_owned()))?;
            (file, line, Some(last))
        },
        _ => (prefix, last, None),
    };
    if file.is_empty() || line == 0 || column == Some(0) {
        return Err(SourceLookupError::Invalid(spec.to_owned()));
    }
    Ok(Some(ParsedSourceSpec { file, line, column }))
}

fn file_match_rank(actual: &str, requested: &str) -> Option<u8> {
    let actual = normalize_path(actual);
    let requested = normalize_path(requested);
    if actual == requested {
        return Some(3);
    }
    if actual.ends_with(&format!("/{requested}")) {
        return Some(2);
    }
    let actual_name = actual.rsplit('/').next()?;
    let requested_name = requested.rsplit('/').next()?;
    (actual_name == requested_name).then_some(1)
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_owned()
}

fn dwarf_io_error(error: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SourceMap {
        SourceMap::from_ranges([
            SourceRange {
                start: 0x1000,
                end: 0x1008,
                location: SourceLocation {
                    file: r"C:\work\kernel\src\main.rs".to_owned(),
                    line: 40,
                    column: Some(5),
                },
            },
            SourceRange {
                start: 0x1008,
                end: 0x1010,
                location: SourceLocation {
                    file: r"C:\work\kernel\src\main.rs".to_owned(),
                    line: 41,
                    column: Some(9),
                },
            },
            SourceRange {
                start: 0x2000,
                end: 0x2004,
                location: SourceLocation {
                    file: r"C:\work\other\main.rs".to_owned(),
                    line: 40,
                    column: None,
                },
            },
        ])
    }

    #[test]
    fn looks_up_half_open_address_ranges() {
        let map = fixture();
        assert_eq!(map.lookup(0x1007).unwrap().line, 40);
        assert_eq!(map.lookup(0x1008).unwrap().line, 41);
        assert!(map.lookup(0x1010).is_none());
    }

    #[test]
    fn resolves_full_and_suffix_paths_deterministically() {
        let map = fixture();
        assert_eq!(map.resolve("kernel/src/main.rs:40"), Ok(Some(0x1000)));
        assert_eq!(
            map.resolve(r"C:\work\kernel\src\main.rs:41"),
            Ok(Some(0x1008))
        );
        assert_eq!(
            map.resolve(r"C:\work\kernel\src\main.rs:41:9"),
            Ok(Some(0x1008))
        );
        assert_eq!(
            map.resolve(&map.lookup(0x1008).unwrap().to_string()),
            Ok(Some(0x1008))
        );
    }

    #[test]
    fn rejects_ambiguous_basenames() {
        let error = fixture().resolve("main.rs:40").unwrap_err();
        assert!(matches!(error, SourceLookupError::Ambiguous { .. }));
    }
}

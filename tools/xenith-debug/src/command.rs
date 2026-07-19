//! User-facing commands translated into the emulator's canonical protocol.

use std::fmt;

use crate::{SourceLookupError, SymbolTable};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedCommand {
    Remote(String),
    Local(String),
    Empty,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandError {
    MissingArgument(&'static str),
    TooManyArguments,
    InvalidNumber(String),
    UnknownSymbol(String),
    AddressOverflow,
    InvalidHex,
    Source(SourceLookupError),
    UnknownCommand(String),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArgument(name) => write!(formatter, "missing {name}"),
            Self::TooManyArguments => formatter.write_str("too many arguments"),
            Self::InvalidNumber(value) => write!(formatter, "invalid number {value}"),
            Self::UnknownSymbol(name) => write!(formatter, "unknown symbol {name}"),
            Self::AddressOverflow => formatter.write_str("address expression overflow"),
            Self::InvalidHex => formatter.write_str("memory bytes must be even-length hex"),
            Self::Source(error) => error.fmt(formatter),
            Self::UnknownCommand(command) => write!(formatter, "unknown command {command}"),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<SourceLookupError> for CommandError {
    fn from(value: SourceLookupError) -> Self {
        Self::Source(value)
    }
}

pub struct CommandTranslator {
    symbols: Option<SymbolTable>,
}

impl CommandTranslator {
    #[must_use]
    pub const fn new(symbols: Option<SymbolTable>) -> Self {
        Self { symbols }
    }

    #[must_use]
    pub const fn symbols(&self) -> Option<&SymbolTable> {
        self.symbols.as_ref()
    }

    pub fn prepare(&self, input: &str) -> Result<PreparedCommand, CommandError> {
        let mut fields = input.split_ascii_whitespace();
        let Some(command) = fields.next() else {
            return Ok(PreparedCommand::Empty);
        };
        let prepared = match command {
            "break" | "b" => {
                let address = self.resolve(one(&mut fields, "address or symbol")?)?;
                end(&mut fields)?;
                PreparedCommand::Remote(format!("break {address:#x}"))
            },
            "delete" | "d" => {
                let address = self.resolve(one(&mut fields, "address or symbol")?)?;
                end(&mut fields)?;
                PreparedCommand::Remote(format!("delete {address:#x}"))
            },
            "step" | "s" => {
                end(&mut fields)?;
                PreparedCommand::Remote("step".to_string())
            },
            "continue" | "c" => {
                let limit = fields.next();
                end(&mut fields)?;
                match limit {
                    Some(value) => {
                        PreparedCommand::Remote(format!("continue {}", parse_number(value)?))
                    },
                    None => PreparedCommand::Remote("continue".to_string()),
                }
            },
            "registers" | "regs" => {
                end(&mut fields)?;
                PreparedCommand::Remote("registers".to_string())
            },
            "reg" => {
                let name = one(&mut fields, "register name")?;
                end(&mut fields)?;
                PreparedCommand::Remote(format!("read-register {name}"))
            },
            "setreg" => {
                let name = one(&mut fields, "register name")?;
                let value = parse_number(one(&mut fields, "value")?)?;
                end(&mut fields)?;
                PreparedCommand::Remote(format!("write-register {name} {value:#x}"))
            },
            "read" | "x" => {
                let address = self.resolve(one(&mut fields, "address or symbol")?)?;
                let length = parse_number(one(&mut fields, "length")?)?;
                end(&mut fields)?;
                PreparedCommand::Remote(format!("read-memory {address:#x} {length}"))
            },
            "write" => {
                let address = self.resolve(one(&mut fields, "address or symbol")?)?;
                let bytes = one(&mut fields, "hex bytes")?;
                if !bytes.len().is_multiple_of(2)
                    || !bytes.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(CommandError::InvalidHex);
                }
                end(&mut fields)?;
                PreparedCommand::Remote(format!("write-memory {address:#x} {bytes}"))
            },
            "breakpoints" => {
                end(&mut fields)?;
                PreparedCommand::Remote("breakpoints".to_string())
            },
            "watch" => {
                let address = self.resolve(one(&mut fields, "address or symbol")?)?;
                let length = parse_number(one(&mut fields, "length")?)?;
                end(&mut fields)?;
                PreparedCommand::Remote(format!("watch {address:#x} {length}"))
            },
            "unwatch" => {
                let address = self.resolve(one(&mut fields, "address or symbol")?)?;
                end(&mut fields)?;
                PreparedCommand::Remote(format!("unwatch {address:#x}"))
            },
            "watchpoints" => {
                end(&mut fields)?;
                PreparedCommand::Remote("watchpoints".to_string())
            },
            "backtrace" | "bt" => {
                let limit = fields.next();
                end(&mut fields)?;
                match limit {
                    Some(value) => {
                        PreparedCommand::Remote(format!("backtrace {}", parse_number(value)?))
                    },
                    None => PreparedCommand::Remote("backtrace".to_string()),
                }
            },
            "status" => {
                end(&mut fields)?;
                PreparedCommand::Remote("status".to_string())
            },
            "quit" | "q" => {
                end(&mut fields)?;
                PreparedCommand::Remote("quit".to_string())
            },
            "symbol" => {
                let name = one(&mut fields, "symbol name")?;
                end(&mut fields)?;
                let symbol = self
                    .symbols
                    .as_ref()
                    .and_then(|symbols| symbols.get(name))
                    .ok_or_else(|| CommandError::UnknownSymbol(name.to_string()))?;
                let mut output = format!(
                    "{:#018x} {} size={} kind={:?}",
                    symbol.address, symbol.name, symbol.size, symbol.kind
                );
                if let Some(location) = self
                    .symbols
                    .as_ref()
                    .and_then(|symbols| symbols.source_at(symbol.address))
                {
                    output.push_str(&format!(" at {location}"));
                }
                PreparedCommand::Local(output)
            },
            "lookup" => {
                let address = self.resolve(one(&mut fields, "address")?)?;
                end(&mut fields)?;
                PreparedCommand::Local(self.describe_address(address)?)
            },
            "source" | "where" => {
                let address = self.resolve(one(&mut fields, "address, symbol, or file:line")?)?;
                end(&mut fields)?;
                let location = self
                    .symbols
                    .as_ref()
                    .and_then(|symbols| symbols.source_at(address))
                    .ok_or_else(|| SourceLookupError::NotFound(format!("{address:#x}")))?;
                PreparedCommand::Local(format!("{address:#018x} {location}"))
            },
            "info" => {
                end(&mut fields)?;
                let symbols = self
                    .symbols
                    .as_ref()
                    .ok_or_else(|| CommandError::UnknownSymbol("no ELF was loaded".to_owned()))?;
                PreparedCommand::Local(format!(
                    "symbols={} dwarf_ranges={} source_files={} image={} load_bias={:#x}",
                    symbols.len(),
                    symbols.sources().len(),
                    symbols.sources().file_count(),
                    if symbols.is_position_independent() {
                        "pie"
                    } else {
                        "exec"
                    },
                    symbols.load_bias()
                ))
            },
            _ => return Err(CommandError::UnknownCommand(command.to_string())),
        };
        Ok(prepared)
    }

    /// Symbolicate the emulator's raw frame-pointer backtrace response while
    /// leaving every other one-line protocol response unchanged.
    #[must_use]
    pub fn format_response(&self, command: &str, response: &str) -> String {
        if !command.starts_with("backtrace") {
            return response.to_owned();
        }
        let Some(addresses) = response.strip_prefix("ok backtrace") else {
            return response.to_owned();
        };
        let mut frames = Vec::new();
        for (index, value) in addresses.split_ascii_whitespace().enumerate() {
            let Ok(address) = parse_number(value) else {
                return response.to_owned();
            };
            let description = self
                .describe_address(address)
                .unwrap_or_else(|_| format!("{address:#018x}"));
            frames.push(format!("#{index} {description}"));
        }
        if frames.is_empty() {
            response.to_owned()
        } else {
            frames.join("\n")
        }
    }

    pub fn resolve(&self, expression: &str) -> Result<u64, CommandError> {
        if let Ok(value) = parse_number(expression) {
            return Ok(value);
        }
        if let Some(symbols) = &self.symbols {
            if let Some(address) = symbols.resolve_source(expression)? {
                return Ok(address);
            }
        }
        if let Some((name, operator, offset)) = split_expression(expression) {
            let base = self.resolve_symbol(name)?;
            let offset = parse_number(offset)?;
            return match operator {
                '+' => base
                    .checked_add(offset)
                    .ok_or(CommandError::AddressOverflow),
                '-' => base
                    .checked_sub(offset)
                    .ok_or(CommandError::AddressOverflow),
                _ => unreachable!(),
            };
        }
        self.resolve_symbol(expression)
    }

    fn resolve_symbol(&self, name: &str) -> Result<u64, CommandError> {
        self.symbols
            .as_ref()
            .and_then(|symbols| symbols.resolve(name))
            .ok_or_else(|| CommandError::UnknownSymbol(name.to_string()))
    }

    fn describe_address(&self, address: u64) -> Result<String, CommandError> {
        let symbols = self
            .symbols
            .as_ref()
            .ok_or_else(|| CommandError::UnknownSymbol(format!("at {address:#x}")))?;
        let symbol = symbols.nearest(address);
        let source = symbols.source_at(address);
        if symbol.is_none() && source.is_none() {
            return Err(CommandError::UnknownSymbol(format!("at {address:#x}")));
        }

        let mut output = format!("{address:#018x}");
        if let Some((symbol, offset)) = symbol {
            output.push_str(&format!(" {}+{offset:#x}", symbol.name));
        }
        if let Some(source) = source {
            output.push_str(&format!(" at {source}"));
        }
        Ok(output)
    }
}

fn parse_number(value: &str) -> Result<u64, CommandError> {
    let result = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    result.map_err(|_| CommandError::InvalidNumber(value.to_string()))
}

fn split_expression(value: &str) -> Option<(&str, char, &str)> {
    value
        .char_indices()
        .skip(1)
        .find(|(_, character)| matches!(character, '+' | '-'))
        .map(|(index, operator)| (&value[..index], operator, &value[index + 1..]))
}

fn one<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    name: &'static str,
) -> Result<&'a str, CommandError> {
    fields.next().ok_or(CommandError::MissingArgument(name))
}

fn end<'a>(fields: &mut impl Iterator<Item = &'a str>) -> Result<(), CommandError> {
    if fields.next().is_some() {
        Err(CommandError::TooManyArguments)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceLocation, SourceMap, SourceRange, Symbol, SymbolKind};

    fn translator() -> CommandTranslator {
        let symbol = Symbol {
            name: "_start".to_string(),
            address: 0x1000,
            size: 16,
            kind: SymbolKind::Function,
            global: true,
        };
        let sources = SourceMap::from_ranges([SourceRange {
            start: 0x1000,
            end: 0x1010,
            location: SourceLocation {
                file: "kernel/src/main.rs".to_owned(),
                line: 12,
                column: Some(3),
            },
        }]);
        CommandTranslator::new(Some(
            SymbolTable::from_symbols([symbol]).with_sources(sources),
        ))
    }

    #[test]
    fn resolves_symbols_and_offsets_for_breakpoints() {
        let translator = translator();
        assert_eq!(
            translator.prepare("break _start+0x4").unwrap(),
            PreparedCommand::Remote("break 0x1004".to_string())
        );
        assert_eq!(translator.resolve("_start-1"), Ok(0x0fff));
    }

    #[test]
    fn translates_memory_and_register_commands() {
        let translator = translator();
        assert_eq!(
            translator.prepare("read _start 16").unwrap(),
            PreparedCommand::Remote("read-memory 0x1000 16".to_string())
        );
        assert_eq!(
            translator.prepare("setreg rip 0x2000").unwrap(),
            PreparedCommand::Remote("write-register rip 0x2000".to_string())
        );
        assert_eq!(
            translator.prepare("watch _start+4 8").unwrap(),
            PreparedCommand::Remote("watch 0x1004 8".to_string())
        );
        assert_eq!(
            translator.prepare("bt 12").unwrap(),
            PreparedCommand::Remote("backtrace 12".to_string())
        );
    }

    #[test]
    fn resolves_source_breakpoints_and_describes_dwarf_locations() {
        let translator = translator();
        assert_eq!(
            translator.prepare("break main.rs:12").unwrap(),
            PreparedCommand::Remote("break 0x1000".to_owned())
        );
        assert_eq!(
            translator.prepare("lookup _start+4").unwrap(),
            PreparedCommand::Local(
                "0x0000000000001004 _start+0x4 at kernel/src/main.rs:12:3".to_owned()
            )
        );
        assert_eq!(
            translator.prepare("source 0x1008").unwrap(),
            PreparedCommand::Local("0x0000000000001008 kernel/src/main.rs:12:3".to_owned())
        );
    }

    #[test]
    fn symbolicates_raw_backtrace_responses() {
        let translator = translator();
        assert_eq!(
            translator.format_response(
                "backtrace 8",
                "ok backtrace 0x0000000000001004 0x0000000000001008"
            ),
            concat!(
                "#0 0x0000000000001004 _start+0x4 at kernel/src/main.rs:12:3\n",
                "#1 0x0000000000001008 _start+0x8 at kernel/src/main.rs:12:3"
            )
        );
        assert_eq!(
            translator.format_response("continue", "stop halted 0x1010"),
            "stop halted 0x1010"
        );
    }
}

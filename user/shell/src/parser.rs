//! Allocation-free shell lexer and pipeline parser.

pub const MAX_STAGES: usize = 8;
pub const MAX_ARGUMENTS: usize = 32;
pub const STORAGE_CAPACITY: usize = 512;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Span {
    start: u16,
    length: u16,
}

impl Span {
    fn new(start: usize, length: usize) -> Self {
        Self {
            start: start as u16,
            length: length as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputRedirection {
    pub path: Span,
    pub append: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage {
    arguments: [Span; MAX_ARGUMENTS],
    argument_count: usize,
    pub input: Option<Span>,
    pub output: Option<OutputRedirection>,
}

impl Stage {
    const fn empty() -> Self {
        Self {
            arguments: [Span {
                start: 0,
                length: 0,
            }; MAX_ARGUMENTS],
            argument_count: 0,
            input: None,
            output: None,
        }
    }

    #[must_use]
    pub const fn argument_count(&self) -> usize {
        self.argument_count
    }

    #[must_use]
    pub fn argument(&self, index: usize) -> Option<Span> {
        (index < self.argument_count).then_some(self.arguments[index])
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParsedLine {
    storage: [u8; STORAGE_CAPACITY],
    storage_len: usize,
    stages: [Stage; MAX_STAGES],
    stage_count: usize,
    background: bool,
}

impl ParsedLine {
    const fn empty() -> Self {
        Self {
            storage: [0; STORAGE_CAPACITY],
            storage_len: 0,
            stages: [Stage::empty(); MAX_STAGES],
            stage_count: 1,
            background: false,
        }
    }

    #[must_use]
    pub const fn stage_count(&self) -> usize {
        self.stage_count
    }

    #[must_use]
    pub const fn background(&self) -> bool {
        self.background
    }

    #[must_use]
    pub fn stage(&self, index: usize) -> Option<&Stage> {
        (index < self.stage_count).then_some(&self.stages[index])
    }

    #[must_use]
    pub fn bytes(&self, span: Span) -> &[u8] {
        let start = usize::from(span.start);
        &self.storage[start..start + usize::from(span.length)]
    }

    #[must_use]
    pub fn pointer(&self, span: Span) -> *const u8 {
        // Every span is emitted into `storage` and followed by NUL.
        unsafe { self.storage.as_ptr().add(usize::from(span.start)) }
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), ParseError> {
        if self.storage_len >= self.storage.len() - 1 {
            return Err(ParseError::LineTooLong);
        }
        self.storage[self.storage_len] = byte;
        self.storage_len += 1;
        Ok(())
    }

    fn terminate_word(&mut self) -> Result<(), ParseError> {
        if self.storage_len == self.storage.len() {
            return Err(ParseError::LineTooLong);
        }
        self.storage[self.storage_len] = 0;
        self.storage_len += 1;
        Ok(())
    }

    fn push_argument(&mut self, stage: usize, span: Span) -> Result<(), ParseError> {
        let stage = &mut self.stages[stage];
        if stage.argument_count == MAX_ARGUMENTS {
            return Err(ParseError::TooManyArguments);
        }
        stage.arguments[stage.argument_count] = span;
        stage.argument_count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Quote {
    Single,
    Double,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Redirect {
    Input,
    Output { append: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    EmptyCommand,
    MissingRedirectionTarget,
    DuplicateRedirection,
    TooManyStages,
    TooManyArguments,
    LineTooLong,
    UnterminatedQuote,
    TrailingEscape,
    BackgroundNotTrailing,
}

fn emit_word(
    parsed: &mut ParsedLine,
    stage: usize,
    start: usize,
    pending: &mut Option<Redirect>,
) -> Result<(), ParseError> {
    let span = Span::new(start, parsed.storage_len - start);
    parsed.terminate_word()?;
    match pending.take() {
        Some(Redirect::Input) => {
            if parsed.stages[stage].input.replace(span).is_some() {
                return Err(ParseError::DuplicateRedirection);
            }
        },
        Some(Redirect::Output { append }) => {
            if parsed.stages[stage]
                .output
                .replace(OutputRedirection { path: span, append })
                .is_some()
            {
                return Err(ParseError::DuplicateRedirection);
            }
        },
        None => parsed.push_argument(stage, span)?,
    }
    Ok(())
}

/// Parse words, single/double quotes, backslash escapes, pipelines, and the
/// `<`, `>`, and `>>` redirection operators. Operators can be adjacent to
/// words (`cat<input|echo`) and quoted operators remain ordinary bytes.
pub fn parse(line: &[u8]) -> Result<ParsedLine, ParseError> {
    let mut parsed = ParsedLine::empty();
    let mut stage = 0usize;
    let mut pending = None;
    let mut word_start = 0usize;
    let mut word_active = false;
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0usize;

    while index < line.len() {
        let byte = line[index];
        if escaped {
            if !word_active {
                word_start = parsed.storage_len;
                word_active = true;
            }
            parsed.push_byte(byte)?;
            escaped = false;
            index += 1;
            continue;
        }
        match quote {
            Some(Quote::Single) => {
                if byte == b'\'' {
                    quote = None;
                } else {
                    parsed.push_byte(byte)?;
                }
                index += 1;
                continue;
            },
            Some(Quote::Double) => {
                if byte == b'"' {
                    quote = None;
                } else if byte == b'\\' {
                    escaped = true;
                } else {
                    parsed.push_byte(byte)?;
                }
                index += 1;
                continue;
            },
            None => {},
        }

        match byte {
            b'\\' => {
                if !word_active {
                    word_start = parsed.storage_len;
                    word_active = true;
                }
                escaped = true;
            },
            b'\'' | b'"' => {
                if !word_active {
                    word_start = parsed.storage_len;
                    word_active = true;
                }
                quote = Some(if byte == b'\'' {
                    Quote::Single
                } else {
                    Quote::Double
                });
            },
            b'|' | b'<' | b'>' | b'&' => {
                if word_active {
                    emit_word(&mut parsed, stage, word_start, &mut pending)?;
                    word_active = false;
                }
                if pending.is_some() {
                    return Err(ParseError::MissingRedirectionTarget);
                }
                match byte {
                    b'|' => {
                        if parsed.stages[stage].argument_count == 0 {
                            return Err(ParseError::EmptyCommand);
                        }
                        if stage + 1 == MAX_STAGES {
                            return Err(ParseError::TooManyStages);
                        }
                        stage += 1;
                        parsed.stage_count = stage + 1;
                    },
                    b'<' => pending = Some(Redirect::Input),
                    b'>' => {
                        let append = line.get(index + 1).copied() == Some(b'>');
                        pending = Some(Redirect::Output { append });
                        if append {
                            index += 1;
                        }
                    },
                    b'&' => {
                        if parsed.stages[stage].argument_count == 0 {
                            return Err(ParseError::EmptyCommand);
                        }
                        parsed.background = true;
                        index += 1;
                        if line[index..].iter().any(|byte| !byte.is_ascii_whitespace()) {
                            return Err(ParseError::BackgroundNotTrailing);
                        }
                        break;
                    },
                    _ => unreachable!(),
                }
            },
            byte if byte.is_ascii_whitespace() => {
                if word_active {
                    emit_word(&mut parsed, stage, word_start, &mut pending)?;
                    word_active = false;
                }
            },
            _ => {
                if !word_active {
                    word_start = parsed.storage_len;
                    word_active = true;
                }
                parsed.push_byte(byte)?;
            },
        }
        index += 1;
    }

    if escaped {
        return Err(ParseError::TrailingEscape);
    }
    if quote.is_some() {
        return Err(ParseError::UnterminatedQuote);
    }
    if word_active {
        emit_word(&mut parsed, stage, word_start, &mut pending)?;
    }
    if pending.is_some() {
        return Err(ParseError::MissingRedirectionTarget);
    }
    if parsed.stages[stage].argument_count == 0 {
        return Err(ParseError::EmptyCommand);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(parsed: &ParsedLine, stage: usize) -> std::vec::Vec<std::string::String> {
        let stage = parsed.stage(stage).unwrap();
        (0..stage.argument_count())
            .map(|index| {
                std::string::String::from_utf8(
                    parsed.bytes(stage.argument(index).unwrap()).to_vec(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn quotes_escapes_and_empty_arguments_are_preserved() {
        let parsed = parse(br#"echo "two words" 'three|words' four\ five """#).unwrap();
        assert_eq!(words(&parsed, 0), [
            "echo",
            "two words",
            "three|words",
            "four five",
            ""
        ]);
    }

    #[test]
    fn attached_operators_build_pipeline_and_redirections() {
        let parsed = parse(b"cat<input|echo ok>>output").unwrap();
        assert_eq!(parsed.stage_count(), 2);
        assert_eq!(words(&parsed, 0), ["cat"]);
        assert_eq!(
            parsed.bytes(parsed.stage(0).unwrap().input.unwrap()),
            b"input"
        );
        assert_eq!(words(&parsed, 1), ["echo", "ok"]);
        let output = parsed.stage(1).unwrap().output.unwrap();
        assert!(output.append);
        assert_eq!(parsed.bytes(output.path), b"output");
    }

    #[test]
    fn malformed_syntax_is_rejected() {
        assert_eq!(parse(b"| cat"), Err(ParseError::EmptyCommand));
        assert_eq!(parse(b"echo >"), Err(ParseError::MissingRedirectionTarget));
        assert_eq!(parse(b"echo 'oops"), Err(ParseError::UnterminatedQuote));
        assert_eq!(parse(b"cat <a <b"), Err(ParseError::DuplicateRedirection));
        assert_eq!(
            parse(b"echo a & echo b"),
            Err(ParseError::BackgroundNotTrailing)
        );
    }

    #[test]
    fn trailing_ampersand_marks_background_without_becoming_an_argument() {
        let parsed = parse(b"echo '&' | cat >out &  ").unwrap();
        assert!(parsed.background());
        assert_eq!(parsed.stage_count(), 2);
        assert_eq!(words(&parsed, 0), ["echo", "&"]);
        assert_eq!(words(&parsed, 1), ["cat"]);
    }
}

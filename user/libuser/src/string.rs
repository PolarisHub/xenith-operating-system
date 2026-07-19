//! Allocation-free byte string helpers.

#[must_use]
pub fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

pub struct Fields<'a> {
    remaining: &'a [u8],
}

impl<'a> Fields<'a> {
    #[must_use]
    pub const fn new(value: &'a [u8]) -> Self {
        Self { remaining: value }
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = trim_ascii(self.remaining);
        if self.remaining.is_empty() {
            return None;
        }
        let end = self
            .remaining
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(self.remaining.len());
        let (field, rest) = self.remaining.split_at(end);
        self.remaining = rest;
        Some(field)
    }
}

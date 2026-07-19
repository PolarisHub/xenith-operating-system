use crate::Error;

const MAX_PATH_BYTES: usize = 4096;
// FAT32 permits 255 UTF-16 code units, which can occupy up to 1020 UTF-8 bytes.
const MAX_NAME_BYTES: usize = 1020;
const MAX_DEPTH: usize = 64;

#[derive(Debug)]
pub(crate) struct ImagePath {
    display: String,
    components: Vec<String>,
}

impl ImagePath {
    pub(crate) fn parse(input: &str) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(Error::InvalidPath("path is empty"));
        }
        if input.len() > MAX_PATH_BYTES {
            return Err(Error::InvalidPath("path is longer than 4096 bytes"));
        }
        if input.contains('\0') {
            return Err(Error::InvalidPath("path contains NUL"));
        }

        let mut components = Vec::new();
        for component in input.split('/') {
            match component {
                "" | "." => {},
                ".." => return Err(Error::InvalidPath("parent components are not accepted")),
                value => {
                    if value.len() > MAX_NAME_BYTES {
                        return Err(Error::InvalidPath("component is longer than 1020 bytes"));
                    }
                    components.push(value.to_owned());
                    if components.len() > MAX_DEPTH {
                        return Err(Error::InvalidPath("path is deeper than 64 components"));
                    }
                },
            }
        }

        let display = if components.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", components.join("/"))
        };
        Ok(Self {
            display,
            components,
        })
    }

    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) fn components(&self) -> &[String] {
        &self.components
    }
}

pub(crate) fn child_path(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{parent}/{child}")
    }
}

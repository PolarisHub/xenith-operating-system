use std::error::Error;
use std::io;
use std::path::Path;

use xenith_debug::SymbolTable;

#[test]
#[ignore = "requires build/kernel.elf from `xenith-build kernel`"]
fn built_kernel_supports_bidirectional_dwarf_line_lookup() -> Result<(), Box<dyn Error>> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("debugger crate must be inside the workspace");
    let kernel = workspace.join("build/kernel.elf");
    let symbols = SymbolTable::load(&kernel)?;

    assert!(!symbols.is_empty(), "kernel ELF has no symbols");
    assert!(
        !symbols.sources().is_empty(),
        "kernel ELF has no DWARF line ranges"
    );

    let (address, location) = symbols
        .iter()
        .find_map(|symbol| {
            symbols
                .source_at(symbol.address)
                .map(|location| (symbol.address, location.clone()))
        })
        .or_else(|| {
            symbols.iter().find_map(|symbol| {
                (0..symbol.size.min(256)).find_map(|offset| {
                    let address = symbol.address.checked_add(offset)?;
                    symbols
                        .source_at(address)
                        .map(|location| (address, location.clone()))
                })
            })
        })
        .ok_or_else(|| io::Error::other("kernel DWARF does not cover an ELF function symbol"))?;

    // The exact location printed by the debugger must also be accepted as a
    // breakpoint expression, including a non-zero DWARF column when present.
    let spec = location.to_string();
    let reverse = symbols.resolve_source(&spec)?.ok_or_else(|| {
        io::Error::other(format!("{spec} was not recognized as a source location"))
    })?;
    let reverse_location = symbols.source_at(reverse).ok_or_else(|| {
        io::Error::other(format!(
            "resolved {spec} to an unmapped address {reverse:#x}"
        ))
    })?;

    assert_eq!(reverse_location.file, location.file);
    assert_eq!(reverse_location.line, location.line);
    assert!(symbols.source_at(address).is_some());
    Ok(())
}

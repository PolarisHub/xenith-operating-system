//! Build orchestration helpers shared by the CLI and tests.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{fs, io};

pub const KERNEL_TARGET: &str = "kernel/x86_64-xenith.json";
pub const KERNEL_TARGET_NAME: &str = "x86_64-xenith";
pub const USER_TARGET: &str = "user/x86_64-xenith-user.json";
pub const USER_TARGET_NAME: &str = "x86_64-xenith-user";

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF_ET_EXEC: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_PT_LOAD: u32 = 1;
const ELF_PF_EXECUTE: u32 = 1;
const ELF_PF_WRITE: u32 = 2;
const USER_IMAGE_MIN: u64 = 0x1000;
const USER_IMAGE_MAX: u64 = 0x0000_7fff_ffff_ffff;

#[derive(Debug)]
pub enum BuildError {
    Io(io::Error),
    Command { program: String, status: i32 },
    Missing(PathBuf),
    InvalidUserspaceElf { path: PathBuf, reason: String },
    Toolchain(xenith_cc::CompileError),
    Image(xenith_iso::ImageError),
    Usage(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Command { program, status } => {
                write!(f, "{program} failed with exit status {status}")
            },
            Self::Missing(path) => write!(f, "required artifact is missing: {}", path.display()),
            Self::InvalidUserspaceElf { path, reason } => {
                write!(f, "invalid userspace ELF {}: {reason}", path.display())
            },
            Self::Toolchain(error) => write!(f, "Xenith C toolchain failed: {error}"),
            Self::Image(error) => write!(f, "image build failed: {error}"),
            Self::Usage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<io::Error> for BuildError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<xenith_iso::ImageError> for BuildError {
    fn from(value: xenith_iso::ImageError) -> Self {
        Self::Image(value)
    }
}

impl From<xenith_cc::CompileError> for BuildError {
    fn from(value: xenith_cc::CompileError) -> Self {
        Self::Toolchain(value)
    }
}

#[derive(Clone, Debug)]
pub struct Layout {
    pub root: PathBuf,
    pub output: PathBuf,
}

impl Layout {
    pub fn discover(start: &Path) -> Result<Self, BuildError> {
        for ancestor in start.ancestors() {
            if ancestor.join("Cargo.toml").is_file()
                && ancestor.join("kernel/x86_64-xenith.json").is_file()
                && ancestor.join("user/x86_64-xenith-user.json").is_file()
            {
                return Ok(Self {
                    root: ancestor.to_path_buf(),
                    output: ancestor.join("build"),
                });
            }
        }
        Err(BuildError::Usage(
            "could not locate Xenith workspace root".to_owned(),
        ))
    }

    fn target_release(&self, target: &str, name: &str) -> PathBuf {
        self.root
            .join("target")
            .join(target)
            .join("release")
            .join(name)
    }

    pub fn kernel_release(&self, name: &str) -> PathBuf {
        self.target_release(KERNEL_TARGET_NAME, name)
    }

    pub fn user_release(&self, name: &str) -> PathBuf {
        self.target_release(USER_TARGET_NAME, name)
    }
}

pub fn run_cargo(layout: &Layout, arguments: &[&str]) -> Result<(), BuildError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let display = format!("cargo {}", arguments.join(" "));
    let status = Command::new(cargo)
        .args(arguments)
        .current_dir(&layout.root)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(BuildError::Command {
            program: display,
            status: status.code().unwrap_or(-1),
        })
    }
}

pub fn build_kernel(layout: &Layout) -> Result<PathBuf, BuildError> {
    run_cargo(layout, &[
        "build",
        "-p",
        "xenith-kernel",
        "--bin",
        "xenith",
        "--release",
        "--target",
        KERNEL_TARGET,
        "-Z",
        "build-std=core,alloc,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ])?;
    fs::create_dir_all(&layout.output)?;
    copy_required(
        &layout.kernel_release("xenith"),
        &layout.output.join("kernel.elf"),
    )
}

fn host_target(layout: &Layout) -> Result<String, BuildError> {
    let output = Command::new("rustc")
        .arg("-vV")
        .current_dir(&layout.root)
        .output()?;
    if !output.status.success() {
        return Err(BuildError::Command {
            program: "rustc -vV".to_owned(),
            status: output.status.code().unwrap_or(-1),
        });
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .ok_or_else(|| BuildError::Usage("rustc did not report a host target".to_owned()))
}

pub fn build_bootloader(layout: &Layout) -> Result<Vec<PathBuf>, BuildError> {
    let host = host_target(layout)?;
    let source_output = layout.root.join("bootloader/build");
    fs::create_dir_all(&source_output)?;
    let stage1 = source_output.join("stage1.bin");
    let stage2_elf = source_output.join("stage2.elf");
    let stage2 = source_output.join("stage2.bin");
    let uefi = source_output.join("BOOTX64.EFI");

    run_cargo(layout, &[
        "run",
        "--quiet",
        "--manifest-path",
        "bootloader/stage1/Cargo.toml",
        "--target",
        &host,
        "--release",
        "--",
        "--output",
        stage1
            .to_str()
            .ok_or_else(|| BuildError::Usage("bootloader output path is not UTF-8".to_owned()))?,
    ])?;
    run_cargo(layout, &[
        "build",
        "--quiet",
        "--manifest-path",
        "bootloader/stage2/Cargo.toml",
        "--target",
        "x86_64-unknown-none",
        "--release",
        "--features",
        "bios-bin",
        "--bin",
        "xenith-stage2",
    ])?;
    copy_required(
        &layout
            .root
            .join("bootloader/stage2/target/x86_64-unknown-none/release/xenith-stage2"),
        &stage2_elf,
    )?;
    run_cargo(layout, &[
        "run",
        "--quiet",
        "--manifest-path",
        "bootloader/stage2/Cargo.toml",
        "--target",
        &host,
        "--release",
        "--features",
        "host-tool",
        "--bin",
        "xenith-stage2-pack",
        "--",
        stage2_elf
            .to_str()
            .ok_or_else(|| BuildError::Usage("stage2 ELF path is not UTF-8".to_owned()))?,
        stage2
            .to_str()
            .ok_or_else(|| BuildError::Usage("stage2 output path is not UTF-8".to_owned()))?,
    ])?;
    run_cargo(layout, &[
        "build",
        "--quiet",
        "--manifest-path",
        "bootloader/uefi/Cargo.toml",
        "--target",
        "x86_64-unknown-uefi",
        "--release",
        "--features",
        "uefi-app",
        "--bin",
        "xenith-bootx64",
    ])?;
    copy_required(
        &layout
            .root
            .join("bootloader/uefi/target/x86_64-unknown-uefi/release/xenith-bootx64.efi"),
        &uefi,
    )?;

    let stage1_bytes = fs::read(&stage1)?;
    if stage1_bytes.len() != 512 || stage1_bytes[510..] != [0x55, 0xaa] {
        return Err(BuildError::Usage(
            "stage1 is not a 512-byte sector with the 0x55AA BIOS boot signature".to_owned(),
        ));
    }
    let stage2_len = fs::metadata(&stage2)?.len();
    if stage2_len == 0 || !stage2_len.is_multiple_of(512) || stage2_len > 127 * 512 {
        return Err(BuildError::Usage(
            "stage2 violates the BIOS transfer bound".to_owned(),
        ));
    }
    let uefi_bytes = fs::read(&uefi)?;
    if uefi_bytes.len() < 256 || !uefi_bytes.starts_with(b"MZ") {
        return Err(BuildError::Usage(
            "UEFI loader is not a PE image".to_owned(),
        ));
    }

    let destination = layout.output.join("bootloader");
    fs::create_dir_all(&destination)?;
    [stage1, stage2_elf, stage2, uefi]
        .iter()
        .map(|source| {
            let name = source
                .file_name()
                .ok_or_else(|| BuildError::Missing(source.clone()))?;
            copy_required(source, &destination.join(name))
        })
        .collect()
}

pub fn build_userspace(layout: &Layout) -> Result<Vec<(String, PathBuf)>, BuildError> {
    run_cargo(layout, &[
        "build",
        "-p",
        "xenith-init",
        "-p",
        "xenith-sh",
        "-p",
        "xenith-coreutils",
        "-p",
        "xenith-editor",
        "-p",
        "xenith-net",
        "-p",
        "xenith-examples",
        "-p",
        "xenith-libc",
        "--release",
        "--target",
        USER_TARGET,
        "-Z",
        "build-std=core,alloc,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ])?;
    let user_dir = layout.output.join("user");
    fs::create_dir_all(&user_dir)?;
    let rust_programs = [
        ("init", "init"),
        ("bin/sh", "xenith-sh"),
        ("bin/coreutils", "xenith-coreutils"),
        ("bin/editor", "xenith-editor"),
        ("bin/xenith-net", "xenith-net"),
        ("bin/hello", "xenith-hello"),
    ];
    for (_, binary) in &rust_programs {
        validate_userspace_elf(&layout.user_release(binary))?;
    }
    let mut programs = rust_programs
        .into_iter()
        .map(|(archive, binary)| {
            let destination = user_dir.join(binary);
            copy_required(&layout.user_release(binary), &destination)?;
            Ok((archive.to_owned(), destination))
        })
        .collect::<Result<Vec<_>, BuildError>>()?;

    let c_source_path = layout.root.join("user/c/xenith-c-demo.c");
    let c_source = fs::read_to_string(&c_source_path)?;
    let c_image = xenith_cc::compile(&c_source)?;
    let c_destination = user_dir.join("xenith-c-demo");
    fs::write(&c_destination, c_image)?;
    validate_userspace_elf(&c_destination)?;
    programs.push(("bin/c-demo".to_owned(), c_destination));
    Ok(programs)
}

fn elf_u16(image: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(image.get(offset..end)?.try_into().ok()?))
}

fn elf_u32(image: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(image.get(offset..end)?.try_into().ok()?))
}

fn elf_u64(image: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    Some(u64::from_le_bytes(image.get(offset..end)?.try_into().ok()?))
}

fn validate_userspace_elf(path: &Path) -> Result<(), BuildError> {
    if !path.is_file() {
        return Err(BuildError::Missing(path.to_path_buf()));
    }
    let image = fs::read(path)?;
    validate_userspace_elf_bytes(&image).map_err(|reason| BuildError::InvalidUserspaceElf {
        path: path.to_path_buf(),
        reason,
    })
}

fn validate_userspace_elf_bytes(image: &[u8]) -> Result<(), String> {
    if image.len() < ELF64_HEADER_SIZE {
        return Err("file is shorter than an ELF64 header".to_owned());
    }
    if image.get(..4) != Some(b"\x7fELF") {
        return Err("bad ELF magic".to_owned());
    }
    if image[4] != 2 {
        return Err("ELF class is not 64-bit".to_owned());
    }
    if image[5] != 1 {
        return Err("ELF byte order is not little-endian".to_owned());
    }
    if image[6] != 1 || elf_u32(image, 20) != Some(1) {
        return Err("unsupported ELF version".to_owned());
    }
    let file_type = elf_u16(image, 16).ok_or("truncated ELF type")?;
    if file_type != ELF_ET_EXEC {
        return Err(format!("ELF type {file_type:#x} is not ET_EXEC"));
    }
    let machine = elf_u16(image, 18).ok_or("truncated ELF machine")?;
    if machine != ELF_MACHINE_X86_64 {
        return Err(format!("ELF machine {machine:#x} is not x86-64"));
    }
    if elf_u16(image, 52) != Some(ELF64_HEADER_SIZE as u16) {
        return Err("invalid ELF64 header size".to_owned());
    }

    let entry = elf_u64(image, 24).ok_or("truncated ELF entry")?;
    if !(USER_IMAGE_MIN..=USER_IMAGE_MAX).contains(&entry) {
        return Err(format!(
            "entry {entry:#x} is outside the user address range"
        ));
    }

    let program_offset = usize::try_from(elf_u64(image, 32).ok_or("truncated program offset")?)
        .map_err(|_| "program header offset does not fit usize")?;
    let program_size = usize::from(elf_u16(image, 54).ok_or("truncated program header size")?);
    if program_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "program header size {program_size} is not {ELF64_PROGRAM_HEADER_SIZE}"
        ));
    }
    let program_count = usize::from(elf_u16(image, 56).ok_or("truncated program header count")?);
    if program_count == 0 {
        return Err("ELF has no program headers".to_owned());
    }
    let table_size = program_count
        .checked_mul(program_size)
        .ok_or("program header table size overflows")?;
    let table_end = program_offset
        .checked_add(table_size)
        .ok_or("program header table range overflows")?;
    if table_end > image.len() {
        return Err("program header table is truncated".to_owned());
    }

    let mut load_count = 0usize;
    let mut entry_is_executable = false;
    for index in 0..program_count {
        let header = program_offset + index * program_size;
        if elf_u32(image, header) != Some(ELF_PT_LOAD) {
            continue;
        }
        load_count += 1;
        let flags = elf_u32(image, header + 4).ok_or("truncated PT_LOAD flags")?;
        if flags & (ELF_PF_WRITE | ELF_PF_EXECUTE) == ELF_PF_WRITE | ELF_PF_EXECUTE {
            return Err(format!("PT_LOAD {index} is writable and executable"));
        }
        let file_offset = elf_u64(image, header + 8).ok_or("truncated PT_LOAD offset")?;
        let virtual_address =
            elf_u64(image, header + 16).ok_or("truncated PT_LOAD virtual address")?;
        let file_size = elf_u64(image, header + 32).ok_or("truncated PT_LOAD file size")?;
        let memory_size = elf_u64(image, header + 40).ok_or("truncated PT_LOAD memory size")?;
        if file_size > memory_size {
            return Err(format!("PT_LOAD {index} has filesz greater than memsz"));
        }
        let file_end = file_offset
            .checked_add(file_size)
            .ok_or_else(|| format!("PT_LOAD {index} file range overflows"))?;
        if file_end > image.len() as u64 {
            return Err(format!("PT_LOAD {index} extends past the file"));
        }
        if memory_size == 0 {
            continue;
        }
        let memory_end = virtual_address
            .checked_add(memory_size)
            .ok_or_else(|| format!("PT_LOAD {index} memory range overflows"))?;
        if virtual_address < USER_IMAGE_MIN || memory_end == 0 || memory_end - 1 > USER_IMAGE_MAX {
            return Err(format!(
                "PT_LOAD {index} range {virtual_address:#x}..{memory_end:#x} is outside the user address range"
            ));
        }
        if flags & ELF_PF_EXECUTE != 0 && (virtual_address..memory_end).contains(&entry) {
            entry_is_executable = true;
        }
    }
    if load_count == 0 {
        return Err("ELF has no PT_LOAD segments".to_owned());
    }
    if !entry_is_executable {
        return Err(format!(
            "entry {entry:#x} is not inside an executable PT_LOAD segment"
        ));
    }
    Ok(())
}

fn copy_required(source: &Path, destination: &Path) -> Result<PathBuf, BuildError> {
    if !source.is_file() {
        return Err(BuildError::Missing(source.to_path_buf()));
    }
    fs::copy(source, destination)?;
    Ok(destination.to_path_buf())
}

fn hex_field(value: u32) -> [u8; 8] {
    let mut result = [b'0'; 8];
    for (index, slot) in result.iter_mut().enumerate() {
        let shift = (7 - index) * 4;
        *slot = b"0123456789abcdef"[((value >> shift) & 0xf) as usize];
    }
    result
}

fn append_newc(output: &mut Vec<u8>, ino: u32, name: &str, mode: u32, data: &[u8]) {
    let mut header = [b'0'; 110];
    header[..6].copy_from_slice(b"070701");
    let values = [
        ino,
        mode,
        0,
        0,
        1,
        0,
        u32::try_from(data.len()).expect("initramfs file exceeds 4 GiB"),
        0,
        0,
        0,
        0,
        u32::try_from(name.len() + 1).expect("initramfs name too long"),
        0,
    ];
    for (index, value) in values.into_iter().enumerate() {
        let start = 6 + index * 8;
        header[start..start + 8].copy_from_slice(&hex_field(value));
    }
    output.extend_from_slice(&header);
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    output.extend_from_slice(data);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
}

pub fn pack_initramfs(
    layout: &Layout,
    programs: &[(String, PathBuf)],
) -> Result<PathBuf, BuildError> {
    let mut archive = Vec::new();
    let mut inode = 1u32;
    append_newc(&mut archive, inode, ".", 0o040755, &[]);
    inode += 1;
    append_newc(&mut archive, inode, "bin", 0o040755, &[]);
    inode += 1;
    for (name, path) in programs {
        append_newc(&mut archive, inode, name, 0o100755, &fs::read(path)?);
        inode += 1;
    }
    let coreutils = programs
        .iter()
        .find(|(name, _)| name == "bin/coreutils")
        .ok_or_else(|| BuildError::Usage("coreutils artifact not supplied".to_owned()))?;
    for utility in [
        "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "echo", "ps", "uname", "date", "sleep",
        "head", "tail", "wc", "touch", "env", "kill", "mount", "umount", "ln", "chmod", "chown",
        "true", "false",
    ] {
        append_newc(
            &mut archive,
            inode,
            &format!("bin/{utility}"),
            0o100755,
            &fs::read(&coreutils.1)?,
        );
        inode += 1;
    }
    for (utility, source_name) in [
        ("ed", "bin/editor"),
        ("vi", "bin/editor"),
        ("ifconfig", "bin/xenith-net"),
        ("ping", "bin/xenith-net"),
        ("nslookup", "bin/xenith-net"),
        ("httpget", "bin/xenith-net"),
        ("telnet", "bin/xenith-net"),
    ] {
        let source = programs
            .iter()
            .find(|(name, _)| name == source_name)
            .ok_or_else(|| BuildError::Usage(format!("{source_name} artifact not supplied")))?;
        append_newc(
            &mut archive,
            inode,
            &format!("bin/{utility}"),
            0o100755,
            &fs::read(&source.1)?,
        );
        inode += 1;
    }
    append_newc(&mut archive, inode, "TRAILER!!!", 0, &[]);
    let path = layout.output.join("initramfs.cpio");
    fs::write(&path, archive)?;
    Ok(path)
}

pub fn build_images(
    layout: &Layout,
    kernel: &Path,
    initrd: &Path,
) -> Result<Vec<PathBuf>, BuildError> {
    let stage1_path = layout.output.join("bootloader/stage1.bin");
    let stage2_path = layout.output.join("bootloader/stage2.bin");
    let uefi_path = layout.output.join("bootloader/BOOTX64.EFI");
    for path in [&stage1_path, &stage2_path, &uefi_path, kernel, initrd] {
        if !path.is_file() {
            return Err(BuildError::Missing(path.to_path_buf()));
        }
    }
    let stage1 = fs::read(stage1_path)?;
    let stage2 = fs::read(stage2_path)?;
    let bootx64 = fs::read(uefi_path)?;
    let kernel = fs::read(kernel)?;
    let initrd = fs::read(initrd)?;
    let disk = xenith_iso::build_disk_image(&stage1, &stage2, &kernel, &initrd)?;
    let disk_path = layout.output.join("xenith.img");
    fs::write(&disk_path, &disk)?;

    let iso = xenith_iso::build_iso_image(
        &disk,
        &bootx64,
        &kernel,
        &initrd,
        &xenith_iso::IsoConfig::default(),
    )?;
    let iso_path = layout.output.join("xenith.iso");
    fs::write(&iso_path, iso)?;
    Ok(vec![disk_path, iso_path])
}

pub fn build_all(layout: &Layout) -> Result<Vec<PathBuf>, BuildError> {
    fs::create_dir_all(&layout.output)?;
    let bootloader = build_bootloader(layout)?;
    let kernel = build_kernel(layout)?;
    let userspace = build_userspace(layout)?;
    let initrd = pack_initramfs(layout, &userspace)?;
    let mut artifacts = bootloader;
    artifacts.extend([kernel.clone(), initrd.clone()]);
    artifacts.extend(userspace.into_iter().map(|(_, path)| path));
    artifacts.extend(build_images(layout, &kernel, &initrd)?);
    let mut manifest = String::new();
    for path in &artifacts {
        let size = fs::metadata(path)?.len();
        let _ = writeln!(manifest, "{size:>10} {}", path.display());
    }
    fs::write(layout.output.join("ARTIFACTS.txt"), manifest)?;
    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newc_header_and_alignment_are_valid() {
        let mut image = Vec::new();
        append_newc(&mut image, 1, "bin/test", 0o100755, b"abc");
        assert!(image.starts_with(b"070701"));
        assert_eq!(image.len() % 4, 0);
        assert_eq!(&image[94..102], b"00000009");
        assert_eq!(&image[54..62], b"00000003");
    }

    #[test]
    fn discovers_workspace() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let layout = Layout::discover(here).unwrap();
        assert!(layout.root.join("kernel").is_dir());
    }

    #[test]
    fn kernel_and_userspace_artifacts_have_distinct_target_directories() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let layout = Layout::discover(here).unwrap();

        assert_ne!(KERNEL_TARGET, USER_TARGET);
        assert_ne!(KERNEL_TARGET_NAME, USER_TARGET_NAME);
        assert_eq!(
            layout.kernel_release("image"),
            layout.root.join("target/x86_64-xenith/release/image")
        );
        assert_eq!(
            layout.user_release("image"),
            layout.root.join("target/x86_64-xenith-user/release/image")
        );
    }

    fn minimal_userspace_elf(entry: u64, load_address: u64) -> Vec<u8> {
        let mut image = vec![0u8; ELF64_HEADER_SIZE + ELF64_PROGRAM_HEADER_SIZE];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&ELF_ET_EXEC.to_le_bytes());
        image[18..20].copy_from_slice(&ELF_MACHINE_X86_64.to_le_bytes());
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        image[24..32].copy_from_slice(&entry.to_le_bytes());
        image[32..40].copy_from_slice(&(ELF64_HEADER_SIZE as u64).to_le_bytes());
        image[52..54].copy_from_slice(&(ELF64_HEADER_SIZE as u16).to_le_bytes());
        image[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        image[56..58].copy_from_slice(&1u16.to_le_bytes());

        let header = ELF64_HEADER_SIZE;
        image[header..header + 4].copy_from_slice(&ELF_PT_LOAD.to_le_bytes());
        image[header + 4..header + 8].copy_from_slice(&5u32.to_le_bytes());
        image[header + 16..header + 24].copy_from_slice(&load_address.to_le_bytes());
        image[header + 24..header + 32].copy_from_slice(&load_address.to_le_bytes());
        image[header + 40..header + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        image[header + 48..header + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        image
    }

    #[test]
    fn accepts_low_half_userspace_elf() {
        let image = minimal_userspace_elf(0x20_0080, 0x20_0000);
        assert_eq!(validate_userspace_elf_bytes(&image), Ok(()));
    }

    #[test]
    fn shipped_c_utility_uses_the_xenith_static_toolchain() {
        let image = xenith_cc::compile(include_str!("../../../user/c/xenith-c-demo.c")).unwrap();
        assert_eq!(validate_userspace_elf_bytes(&image), Ok(()));
        assert_eq!(elf_u16(&image, 56), Some(2));
    }

    #[test]
    fn rejects_kernel_linked_userspace_elf() {
        let image = minimal_userspace_elf(0xffff_ffff_8020_0020, 0xffff_ffff_8020_0000);
        let error = validate_userspace_elf_bytes(&image).unwrap_err();
        assert!(error.contains("entry 0xffffffff80200020"));
        assert!(error.contains("outside the user address range"));
    }

    #[test]
    fn rejects_high_half_userspace_load_segment() {
        let mut image = minimal_userspace_elf(0x20_0080, 0x20_0000);
        let address = 0xffff_ffff_8020_0000u64.to_le_bytes();
        let header = ELF64_HEADER_SIZE;
        image[header + 16..header + 24].copy_from_slice(&address);

        let error = validate_userspace_elf_bytes(&image).unwrap_err();
        assert!(error.contains("PT_LOAD 0 range 0xffffffff80200000"));
        assert!(error.contains("outside the user address range"));
    }
}

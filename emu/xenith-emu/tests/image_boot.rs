use std::fs;
use std::path::Path;

use xenith_boot_common::{DiskEntryKind, DiskManifest};
use xenith_emu::{ExitReason, Machine, MachineConfig};

fn workspace_file(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn assert_packaged_payload(image: &[u8], kind: DiskEntryKind, path: &str) {
    let manifest = DiskManifest::parse(&image[512..1024]).expect("parse packaged manifest");
    let entry = manifest.find(kind).expect("find packaged payload");
    let start = entry.start_lba as usize * 512;
    let end = start + entry.byte_len as usize;
    let expected = fs::read(workspace_file(path)).expect("read independently built payload");
    assert_eq!(
        &image[start..end],
        expected,
        "packaged {path} is stale; rerun `xenith-build all`"
    );
}

#[test]
#[ignore = "requires `xenith-build all`; runs the packaged image for 100M iterations"]
fn manifest_image_reaches_userspace_shell() {
    let image = fs::read(workspace_file("build/xenith.img")).expect("read built raw image");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 128 * 1024 * 1024,
        instruction_limit: 100_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    let manifest = machine
        .load_manifest_image(image, true)
        .expect("validate manifest image and load packaged payloads");
    assert!(manifest.disk_sectors > 0);
    assert!(manifest.kernel_bytes > 0);
    assert!(manifest.initrd_bytes > 0);
    assert!(machine.disk_image().is_some_and(|disk| disk.read_only()));

    let summary = machine.run();
    let serial = String::from_utf8_lossy(&summary.serial);
    assert_eq!(summary.reason, ExitReason::InstructionLimit, "{serial}");
    for marker in [
        "xenith: init",
        "xenith.time.hpet",
        "rtl8139",
        "user: init spawned",
        "Xenith shell 0.1",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing {marker:?}\n{serial}");
    }
}

#[test]
#[ignore = "requires `xenith-build all`; boots the packaged BIOS image for 100M iterations"]
fn bios_firmware_image_reaches_userspace_shell() {
    let image = fs::read(workspace_file("build/xenith.img")).expect("read built raw image");
    let packaged_manifest =
        DiskManifest::parse(&image[512..1024]).expect("parse packaged manifest");
    assert_eq!(
        &image[..512],
        fs::read(workspace_file("build/bootloader/stage1.bin"))
            .expect("read independently built stage1"),
        "packaged stage1 is stale; rerun `xenith-build all`"
    );
    assert_packaged_payload(&image, DiskEntryKind::Stage2, "build/bootloader/stage2.bin");
    assert_packaged_payload(&image, DiskEntryKind::Kernel, "build/kernel.elf");
    assert_packaged_payload(&image, DiskEntryKind::Initrd, "build/initramfs.cpio");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 256 * 1024 * 1024,
        instruction_limit: 100_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    let manifest = machine
        .load_bios_image(image.clone(), true)
        .expect("execute packaged BIOS image through firmware shim");
    assert!(manifest.disk_sectors > 0);
    let trace = machine
        .bios_boot_trace()
        .cloned()
        .expect("BIOS transition trace");
    assert_eq!(trace.reset_vector, 0x000f_fff0);
    assert_eq!(trace.boot_drive, 0x80);
    assert_eq!(trace.stage1_load_address, 0x7c00);
    assert_eq!(
        trace.stage1_checksum,
        xenith_boot_common::fnv1a64(&image[..512])
    );
    assert_eq!(trace.stage2_load_address, 0x8000);
    assert!(trace.stage1_instructions >= 50, "{trace:#?}");
    assert!(trace.stage1_fetched_bytes > trace.stage1_instructions);
    assert_ne!(trace.stage1_execution_checksum, 0);
    assert!(trace.stage2_instructions >= 8_000, "{trace:#?}");
    assert!(trace.stage2_fetched_bytes > trace.stage2_instructions);
    assert_ne!(trace.stage2_execution_checksum, 0);
    let payload_reads = [DiskEntryKind::Kernel, DiskEntryKind::Initrd]
        .into_iter()
        .map(|kind| {
            packaged_manifest
                .find(kind)
                .expect("find preloaded payload")
                .sector_count
                .div_ceil(64)
        })
        .sum::<u64>();
    assert!(
        trace.bios_interrupts >= payload_reads + 7,
        "payload preloads did not issue the expected bounded BIOS reads: {trace:#?}"
    );
    assert!((0x8000..0xc000).contains(&trace.stage2_main_entry));
    assert!(trace.semantic_stage2_loader_fallback);
    assert!(trace.a20_enabled);
    assert!(trace.protected_mode_entered);
    assert!(trace.long_mode_entered);
    assert_eq!(trace.handoff_address, 0x51000);
    let stage2_lba = trace.stage2_lba as usize;
    let stage2_bytes = trace.stage2_sectors as usize * 512;
    let mut loaded_stage2 = vec![0_u8; stage2_bytes];
    machine
        .bus
        .read_physical(trace.stage2_load_address, &mut loaded_stage2)
        .expect("read transferred stage2");
    let packaged_stage2 = &image[stage2_lba * 512..stage2_lba * 512 + stage2_bytes];
    // Stage2 retains runtime disk/VBE/E820 state in its loaded data section,
    // so compare its immutable entry code rather than stale field offsets.
    assert_eq!(&loaded_stage2[..64], &packaged_stage2[..64]);
    assert_eq!(
        trace.stage2_checksum,
        xenith_boot_common::fnv1a64(&image[stage2_lba * 512..stage2_lba * 512 + stage2_bytes])
    );
    let mut handoff_magic = [0_u8; 8];
    machine
        .bus
        .read_physical(trace.handoff_address, &mut handoff_magic)
        .expect("read native handoff header");
    assert_eq!(
        u64::from_le_bytes(handoff_magic),
        xenith_boot_common::XENITH_BOOT_MAGIC
    );

    let summary = machine.run();
    let serial = String::from_utf8_lossy(&summary.serial);
    assert_eq!(summary.reason, ExitReason::InstructionLimit, "{serial}");
    for marker in [
        "xenith: init",
        "user: init spawned",
        "Xenith shell 0.1",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing {marker:?}\n{serial}");
    }
}

#[test]
#[ignore = "requires `xenith-build all`; boots the packaged BIOS image with 64 MiB"]
fn bios_firmware_image_reaches_shell_with_64_mib() {
    let image = fs::read(workspace_file("build/xenith.img")).expect("read built raw image");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 64 * 1024 * 1024,
        instruction_limit: 100_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine
        .load_bios_image(image, true)
        .expect("load compact BIOS payload layout in 64 MiB");

    let summary = machine.run();
    let serial = String::from_utf8_lossy(&summary.serial);
    assert_eq!(summary.reason, ExitReason::InstructionLimit, "{serial}");
    for marker in [
        "xenith.mm.heap: 8192 KiB heap",
        "user: init spawned",
        "Xenith shell 0.1",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing {marker:?}\n{serial}");
    }
}

#[test]
#[ignore = "requires `xenith-build all`; executes the ISO BIOS path and boots three CPUs to the shell"]
fn bios_iso_catalog_entry_executes_packaged_stages_then_semantic_shell() {
    let iso = fs::read(workspace_file("build/xenith.iso")).expect("read built ISO");
    let raw_disk = fs::read(workspace_file("build/xenith.img")).expect("read built raw image");
    let stage1 = fs::read(workspace_file("build/bootloader/stage1.bin"))
        .expect("read independently built stage1");
    let images = xenith_iso::extract_el_torito_boot_images(&iso)
        .expect("select and validate El Torito boot images");
    assert_eq!(images.boot_catalog_lba, 22);
    assert_eq!(&images.bios_disk[..446], &stage1[..446]);
    assert_eq!(&images.bios_disk[510..512], &[0x55, 0xaa]);
    assert_eq!(images.bios_disk[446], 0x80, "partition must be active");
    assert_eq!(images.bios_disk[450], 0xda, "Xenith partition type");
    let raw_sectors = raw_disk.len() / 512;
    let emulated_sectors = raw_sectors.div_ceil(16 * 63) * (16 * 63);
    assert_eq!(images.bios_disk.len(), emulated_sectors * 512);
    assert_eq!(&images.bios_disk[..446], &raw_disk[..446]);
    assert_eq!(&images.bios_disk[510..raw_disk.len()], &raw_disk[510..]);
    assert!(images.bios_disk[raw_disk.len()..]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(
        u32::from_le_bytes(images.bios_disk[458..462].try_into().unwrap()),
        emulated_sectors as u32 - 1
    );
    assert_packaged_payload(
        images.bios_disk,
        DiskEntryKind::Stage2,
        "build/bootloader/stage2.bin",
    );
    assert_packaged_payload(images.bios_disk, DiskEntryKind::Kernel, "build/kernel.elf");
    assert_packaged_payload(
        images.bios_disk,
        DiskEntryKind::Initrd,
        "build/initramfs.cpio",
    );

    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 256 * 1024 * 1024,
        cpu_count: 3,
        instruction_limit: 420_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    let manifest = machine
        .load_bios_iso(&iso, true)
        .expect("boot packaged ISO through its BIOS catalog entry");
    assert!(manifest.disk_sectors > 0);
    assert!(machine.disk_image().is_some_and(|disk| disk.read_only()));
    let trace = machine
        .bios_boot_trace()
        .expect("BIOS ISO transition trace");
    assert_eq!(trace.reset_vector, 0x000f_fff0);
    assert_eq!(trace.boot_drive, 0x80);
    assert_eq!(trace.stage1_load_address, 0x7c00);
    assert_eq!(trace.stage2_load_address, 0x8000);
    assert!(trace.stage1_instructions >= 50, "{trace:#?}");
    assert!(trace.stage2_instructions >= 8_000, "{trace:#?}");
    assert!(trace.a20_enabled);
    assert!(trace.protected_mode_entered);
    assert!(trace.long_mode_entered);
    assert!(
        trace.semantic_stage2_loader_fallback,
        "this gate must not be mistaken for complete real-firmware stage2 execution"
    );

    let mut remaining = 420_000_000;
    let serial = loop {
        let step = remaining.min(10_000_000);
        let summary = machine.run_for(step);
        let serial = String::from_utf8_lossy(&summary.serial).into_owned();
        if serial.contains("xenith$ ") {
            break serial;
        }
        assert_eq!(summary.reason, ExitReason::InstructionLimit, "{serial}");
        remaining -= step;
        assert!(
            remaining != 0,
            "three-CPU BIOS ISO boot did not reach the shell\n{serial}"
        );
    };
    for marker in [
        "xenith: init",
        "xenith.smp: using retired BIOS bounce page 0x70000 for serialized AP startup",
        "xenith.smp: CPU 1 online",
        "xenith.smp: CPU 2 online",
        "xenith.smp: 3 CPU(s) online, 3 discovered",
        "user: init spawned",
        "Xenith shell 0.1",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing {marker:?}\n{serial}");
    }
    assert_eq!(machine.cpu_count(), 3);
    for processor in 0..3 {
        assert!(
            machine
                .cpu_state(processor)
                .is_some_and(|state| state.cycles != 0),
            "CPU {processor} never executed"
        );
    }
}

#[test]
#[ignore = "requires `xenith-build all`; executes packaged BOOTX64.EFI and boots for 100M iterations"]
fn uefi_iso_executes_packaged_pe_and_reaches_userspace_shell() {
    let iso = fs::read(workspace_file("build/xenith.iso")).expect("read built ISO");
    let bootx64 = fs::read(workspace_file("build/bootloader/BOOTX64.EFI"))
        .expect("read independently built BOOTX64.EFI");
    let kernel =
        fs::read(workspace_file("build/kernel.elf")).expect("read independently built kernel");
    let initrd =
        fs::read(workspace_file("build/initramfs.cpio")).expect("read independently built initrd");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 256 * 1024 * 1024,
        instruction_limit: 100_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine
        .load_uefi_iso(&iso)
        .expect("execute packaged UEFI application from platform-0xEF ESP");
    let trace = machine
        .uefi_boot_trace()
        .cloned()
        .expect("UEFI execution trace");
    assert_eq!(trace.boot_catalog_lba, 22);
    assert!(trace.bios_image_lba > trace.boot_catalog_lba);
    assert!(trace.efi_image_lba > trace.bios_image_lba);
    assert_eq!(trace.efi_load_sectors, 32_768);
    assert_eq!(
        trace.bootx64_checksum,
        xenith_boot_common::fnv1a64(&bootx64)
    );
    assert_eq!(trace.kernel_checksum, xenith_boot_common::fnv1a64(&kernel));
    assert_eq!(trace.initrd_checksum, xenith_boot_common::fnv1a64(&initrd));
    assert_ne!(trace.preferred_image_base, trace.image_load_base);
    assert_eq!(trace.image_load_base, 0x0100_0000);
    assert!(trace.pe_instructions > 1_000, "{trace:#?}");
    assert!(trace.pe_fetched_bytes > trace.pe_instructions);
    assert_ne!(trace.pe_execution_checksum, 0);
    assert_eq!(trace.services.handle_protocol, 2);
    assert_eq!(trace.services.open_volume, 1);
    assert_eq!(trace.services.file_open, 2);
    assert_eq!(trace.services.file_get_info, 2);
    assert_eq!(trace.services.file_read, 2);
    assert_eq!(trace.services.file_close, 2);
    assert_eq!(trace.services.locate_protocol, 1);
    assert!(trace.services.allocate_pages >= 8);
    assert!(trace.services.get_memory_map >= 2);
    assert_eq!(trace.services.exit_boot_services, 1);
    assert!(trace.bios_catalog_exact_stage_execution);
    assert!(trace.bios_stage1_instructions >= 50);
    assert!(trace.bios_stage2_instructions >= 8_000);
    assert!(trace.boot_services_exited);
    assert!(!trace.semantic_loader_fallback);
    assert_eq!(trace.rsdp, 0x000e_0000);
    assert_ne!(trace.final_cr3, 0x1000);
    let mut handoff_magic = [0_u8; 8];
    machine
        .bus
        .read_physical(trace.handoff_address, &mut handoff_magic)
        .expect("read UEFI handoff");
    assert_eq!(
        u64::from_le_bytes(handoff_magic),
        xenith_boot_common::XENITH_BOOT_MAGIC
    );

    let summary = machine.run();
    let serial = String::from_utf8_lossy(&summary.serial);
    assert_eq!(summary.reason, ExitReason::InstructionLimit, "{serial}");
    for marker in [
        "xenith: init",
        "user: init spawned",
        "Xenith shell 0.1",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing {marker:?}\n{serial}");
    }
}

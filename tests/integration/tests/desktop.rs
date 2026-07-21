use xenith_emu::{ExitReason, FramebufferConfig};

const BOOT_LIMIT: u64 = 100_000_000;
const FALLBACK_LIMIT: u64 = 30_000_000;
const STABILITY_SLICE: u64 = 2_500_000;
const STABILITY_SAMPLES: usize = 8;
const INTERACTION_LIMIT: u64 = 80_000_000;
// The emulator charges SMP execution against one aggregate round-robin
// budget. Three virtual CPUs therefore need roughly three times the UP boot
// allowance even when every guest CPU is making normal progress.
const SMP_WINDOW_BOOT_LIMIT: u64 = 600_000_000;
const SMP_WINDOW_FALLBACK_LIMIT: u64 = 100_000_000;
const WINDOW_SMOKE_LIMIT: u64 = 500_000_000;
const EXPLORER_LIMIT: u64 = 500_000_000;

fn framebuffer_payload(ppm: &[u8]) -> Option<&[u8]> {
    let mut newlines = 0usize;
    for (index, byte) in ppm.iter().enumerate() {
        if *byte == b'\n' {
            newlines += 1;
            if newlines == 3 {
                return Some(&ppm[index + 1..]);
            }
        }
    }
    None
}

#[test]
#[ignore = "requires `xenith-build all`; run explicitly after the framebuffer ABI gate"]
fn desktop_renders_stays_stable_and_falls_back_to_shell() {
    let mut machine = xenith_integration::load_built_kernel_with_framebuffer(
        BOOT_LIMIT,
        Some(FramebufferConfig {
            width: 320,
            height: 200,
        }),
    )
    .unwrap();
    let before_boot = machine.framebuffer_ppm().unwrap().unwrap();

    let ready =
        xenith_integration::run_until_serial(&mut machine, "XENITH_DESKTOP_READY", 1, BOOT_LIMIT)
            .unwrap();
    assert!(ready.contains("XENITH_DESKTOP_START"));
    assert!(!ready.contains("XENITH_DESKTOP_FAIL"));
    assert!(!ready.contains("XENITH_DESKTOP_FALLBACK"));

    let desktop = machine.framebuffer_ppm().unwrap().unwrap();
    assert_ne!(
        framebuffer_payload(&before_boot).expect("pre-boot framebuffer is a binary PPM image"),
        framebuffer_payload(&desktop).expect("desktop framebuffer is a binary PPM image"),
        "desktop readiness marker was emitted without a visible present"
    );
    let desktop_pixels =
        framebuffer_payload(&desktop).expect("desktop framebuffer is a binary PPM image");
    let first_pixel = &desktop_pixels[..3];
    assert_eq!(
        first_pixel,
        &[186, 183, 176],
        "desktop did not present the embedded Sedat photo at the unobscured origin"
    );
    assert!(
        (3..desktop_pixels.len())
            .step_by(3)
            .any(|offset| &desktop_pixels[offset..offset + 3] != first_pixel),
        "desktop rendered a single flat color instead of the composed shell"
    );

    let mut halted_samples = 0usize;
    for _ in 0..STABILITY_SAMPLES {
        let stable = machine.run_for(STABILITY_SLICE);
        assert_eq!(stable.reason, ExitReason::InstructionLimit);
        halted_samples += usize::from(machine.cpu.state.halted);
    }
    assert!(
        halted_samples >= STABILITY_SAMPLES / 2,
        "idle desktop did not leave the UP processor halted often enough; init may be busy-waiting ({halted_samples}/{STABILITY_SAMPLES} samples)"
    );
    let stable_output = machine.serial_output();
    let stable_serial = String::from_utf8_lossy(&stable_output);
    assert!(!stable_serial.contains("XENITH_DESKTOP_FAIL"));
    assert!(!stable_serial.contains("XENITH_DESKTOP_FALLBACK"));

    xenith_integration::toggle_desktop_launcher(&mut machine).unwrap();
    let interaction = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_DESKTOP_LAUNCHER_OPEN",
        1,
        INTERACTION_LIMIT,
    )
    .unwrap();
    assert!(
        !interaction.contains("XENITH_DESKTOP_FAIL"),
        "desktop failed while opening the launcher: {interaction}"
    );
    let launcher = machine.framebuffer_ppm().unwrap().unwrap();
    assert_ne!(
        framebuffer_payload(&desktop).expect("desktop framebuffer is a binary PPM image"),
        framebuffer_payload(&launcher).expect("launcher framebuffer is a binary PPM image"),
        "Super input did not toggle and damage-present the launcher"
    );

    xenith_integration::request_desktop_exit(&mut machine).unwrap();
    let fallback = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_DESKTOP_FALLBACK",
        1,
        FALLBACK_LIMIT,
    )
    .unwrap();
    assert!(fallback.contains("XENITH_DESKTOP_CLEAN_EXIT"));
    let shell =
        xenith_integration::run_until_serial(&mut machine, "xenith$ ", 1, FALLBACK_LIMIT).unwrap();
    assert!(
        shell.ends_with("xenith$ "),
        "desktop exited, but init did not restore an interactive shell:\n{shell}"
    );
    let terminal = machine.framebuffer_ppm().unwrap().unwrap();
    assert_ne!(
        framebuffer_payload(&desktop).expect("desktop framebuffer is a binary PPM image"),
        framebuffer_payload(&terminal).expect("terminal framebuffer is a binary PPM image"),
        "desktop release did not restore the terminal framebuffer"
    );
}

#[test]
#[ignore = "requires `xenith-build all`; explicit end-to-end compositor smoke"]
fn opt_in_window_client_completes_shared_buffer_protocol() {
    let mut machine = xenith_integration::load_built_kernel_with_framebuffer_and_cpus(
        SMP_WINDOW_BOOT_LIMIT,
        Some(FramebufferConfig {
            width: 320,
            height: 200,
        }),
        3,
    )
    .unwrap();
    xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_DESKTOP_READY",
        1,
        SMP_WINDOW_BOOT_LIMIT,
    )
    .unwrap();
    xenith_integration::request_desktop_exit(&mut machine).unwrap();
    xenith_integration::run_until_serial(&mut machine, "xenith$ ", 1, SMP_WINDOW_FALLBACK_LIMIT)
        .unwrap();

    machine
        .inject_keyboard_ascii("/bin/xenith-desktop --window-smoke --smoke-exit\n")
        .unwrap();
    let output = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_WINDOW_SMOKE_PASS",
        1,
        WINDOW_SMOKE_LIMIT,
    )
    .unwrap();
    assert!(output.contains("XENITH_WINDOW_SMOKE_PRESENTED"));
    assert!(!output.contains("XENITH_WINDOW_SMOKE_FAIL"));
    assert!(!output.contains("XENITH_DESKTOP_FAIL"));

    // The client emits PASS immediately before exiting; endpoint hangup is
    // therefore observed asynchronously by the compositor on its next wait.
    let closed = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_COMPOSITOR_CLIENT_CLOSED",
        1,
        WINDOW_SMOKE_LIMIT,
    )
    .unwrap();
    assert!(!closed.contains("XENITH_WINDOW_SMOKE_FAIL"));
    assert!(!closed.contains("XENITH_DESKTOP_FAIL"));

    xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_DESKTOP_CLEAN_EXIT",
        2,
        SMP_WINDOW_FALLBACK_LIMIT,
    )
    .unwrap();
    let shell = xenith_integration::run_until_serial(
        &mut machine,
        "xenith$ ",
        2,
        SMP_WINDOW_FALLBACK_LIMIT,
    )
    .unwrap();
    assert!(shell.ends_with("xenith$ "));
    assert_eq!(machine.cpu_count(), 3);
    assert!((0..3).all(|processor| machine
        .cpu_state(processor)
        .is_some_and(|state| state.cycles != 0)));
}

#[test]
#[ignore = "requires `xenith-build all`; explicit end-to-end Files app gate"]
fn super_e_launches_a_visible_file_explorer_and_desktop_cleans_it_up() {
    let mut machine = xenith_integration::load_built_kernel_with_framebuffer(
        BOOT_LIMIT,
        Some(FramebufferConfig {
            width: 320,
            height: 200,
        }),
    )
    .unwrap();
    xenith_integration::run_until_serial(&mut machine, "XENITH_DESKTOP_READY", 1, BOOT_LIMIT)
        .unwrap();
    let desktop = machine.framebuffer_ppm().unwrap().unwrap();

    xenith_integration::launch_file_explorer(&mut machine).unwrap();
    let ready = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_EXPLORER_READY",
        1,
        EXPLORER_LIMIT,
    )
    .unwrap();
    assert!(ready.contains("XENITH_EXPLORER_SPAWN"));
    assert!(!ready.contains("XENITH_EXPLORER_FAIL"));
    assert!(!ready.contains("XENITH_DESKTOP_FAIL"));

    let explorer = machine.framebuffer_ppm().unwrap().unwrap();
    assert_ne!(
        framebuffer_payload(&desktop).expect("desktop framebuffer is a binary PPM image"),
        framebuffer_payload(&explorer).expect("explorer framebuffer is a binary PPM image"),
        "Files emitted its ready marker without presenting a visible surface"
    );

    xenith_integration::explorer_submit_address(&mut machine, r"C:\Users\Xenith\AppData").unwrap();
    let navigated = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_EXPLORER_DIRECTORY path=/win/c/Users/Xenith/AppData entries=",
        1,
        EXPLORER_LIMIT,
    )
    .unwrap();
    assert!(!navigated.contains("XENITH_EXPLORER_DIRECTORY_FAIL"));

    xenith_integration::explorer_create_folder(&mut machine).unwrap();
    let created = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_EXPLORER_CREATED path=/win/c/Users/Xenith/AppData/New folder",
        1,
        EXPLORER_LIMIT,
    )
    .unwrap();
    assert!(!created.contains("XENITH_EXPLORER_CREATE_FAIL"));

    xenith_integration::explorer_confirm_delete(&mut machine).unwrap();
    let deleted = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_EXPLORER_DELETED path=/win/c/Users/Xenith/AppData/New folder",
        1,
        EXPLORER_LIMIT,
    )
    .unwrap();
    assert!(!deleted.contains("XENITH_EXPLORER_DELETE_FAIL"));

    xenith_integration::request_desktop_exit(&mut machine).unwrap();
    let explorer_exit = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_EXPLORER_CLEAN_EXIT",
        1,
        EXPLORER_LIMIT,
    )
    .unwrap();
    assert!(!explorer_exit.contains("XENITH_EXPLORER_FAIL"));
    let fallback = xenith_integration::run_until_serial(
        &mut machine,
        "XENITH_DESKTOP_FALLBACK",
        1,
        EXPLORER_LIMIT,
    )
    .unwrap();
    assert!(fallback.contains("XENITH_DESKTOP_CLEAN_EXIT"));
    assert!(!fallback.contains("XENITH_EXPLORER_FAIL"));
}

//! Device subsystem: serial console, framebuffer, VGA, and (later)
//! IOAPIC/PIC routing and bus enumeration.
//!
//! Each driver lives in its own submodule and owns its bring-up. The
//! 16550 UART ([`serial`]) is the first device initialised because every
//! later subsystem reports progress through it.
//!
//! With feature `apic`, the local APIC and IOAPIC replace the legacy PIC;
//! that routing code is added by a later phase alongside the interrupt
//! controller driver.

pub mod ahci;
pub mod audio;
pub mod cmos;
pub mod display;
pub mod driver;
pub mod fb_font;
pub mod framebuffer;
pub mod gfx;
pub mod net;
pub mod pci;
pub mod pcspk;
pub mod ps2;
pub mod registry;
pub mod rng;
pub mod serial;
pub mod serial_ext;
pub mod term;
pub mod usb;
pub mod vga;

// More device modules may be registered by their owners (e.g. the IOAPIC
// or HPET driver) as those land in later phases; each owner adds a `pub mod`
// declaration here via Edit when its file arrives.

/// Device bring-up.
///
/// Runs after the console/log/arch/mm/time subsystems are up. Initialises
/// the 16550 UART on COM1 so the kernel has a polled serial console
/// available to every later subsystem and to the panic handler. Frame-
/// buffer and VGA drivers are brought up by their owning modules
/// (`console` wires the framebuffer; `vga` is driven on demand).
pub fn init(_boot_info: &'static limine::BootInfo) {
    serial::COM1.lock().init();
    ::log::info!("devices: COM1 serial port initialised (38400 8N1)");

    rng::init();

    if let Err(error) = cmos::init() {
        ::log::warn!("devices: CMOS/RTC unavailable: {:?}", error);
    }

    match ps2::init() {
        Ok(()) => {
            ps2::register_irq_handlers();
            if let Err(error) = ps2::keyboard::init() {
                ::log::warn!("devices: PS/2 keyboard unavailable: {:?}", error);
            }
            if ps2::is_dual_channel() {
                if let Err(error) = ps2::mouse::init() {
                    ::log::warn!("devices: PS/2 mouse unavailable: {:?}", error);
                }
            }
        },
        Err(error) => ::log::warn!("devices: PS/2 controller unavailable: {:?}", error),
    }

    ahci::register_pci_driver();
    audio::register_pci_driver();
    display::register_pci_driver();
    net::register_pci_drivers();
    usb::register_pci_driver();
    let pci_count = pci::enumerate::enumerate_and_bind();
    usb::start_service_worker();
    ::log::info!(
        "devices: PCI scan found {} function(s), {} AHCI controller(s), {} HDA controller(s), {} network adapter(s), {} xHCI controller(s), {} USB boot-HID interface(s), VMware SVGA II {}",
        pci_count,
        ahci::controller_count(),
        audio::controller_count(),
        net::adapter_count(),
        usb::controller_count(),
        usb::hid_interface_count(),
        if display::is_attached() {
            "attached"
        } else {
            "absent"
        }
    );
}

//! Serial-first in-kernel test records for bare-metal test images.

#[repr(C)]
pub struct KernelTest {
    pub name: &'static str,
    pub run: fn() -> Result<(), &'static str>,
}

/// Execute a concrete test slice and report deterministic PASS/FAIL markers.
pub fn run(tests: &[KernelTest]) -> usize {
    let mut failed = 0usize;
    ::log::info!("test: running {} kernel tests", tests.len());
    for test in tests {
        match (test.run)() {
            Ok(()) => ::log::info!("test: PASS {}", test.name),
            Err(reason) => {
                failed += 1;
                ::log::error!("test: FAIL {}: {}", test.name, reason);
            },
        }
    }
    ::log::info!("test: complete, {} failed", failed);
    failed
}

/// Declare a test function and a linker-retained test descriptor.
#[macro_export]
macro_rules! kernel_test {
    ($name:ident, $body:block) => {
        fn $name() -> Result<(), &'static str> $body

        const _: () = {
            #[used]
            #[link_section = ".xenith_tests"]
            static TEST: $crate::test::KernelTest = $crate::test::KernelTest {
                name: stringify!($name),
                run: $name,
            };
        };
    };
}

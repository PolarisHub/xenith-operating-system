use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
#[ignore = "requires `xenith-build all`; runs the built kernel and initramfs"]
fn input_script_proves_shell_pipeline_and_redirection() {
    let root = workspace_root();
    let kernel = root.join("build/kernel.elf");
    let initrd = root.join("build/initramfs.cpio");
    assert!(
        kernel.is_file(),
        "missing {}; run xenith-build all",
        kernel.display()
    );
    assert!(
        initrd.is_file(),
        "missing {}; run xenith-build all",
        initrd.display()
    );

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let script = std::env::temp_dir().join(format!(
        "xenith-emu-input-{}-{unique}.txt",
        std::process::id()
    ));
    fs::write(
        &script,
        b"echo PIPE_ARTIFACT > /source\r\ncat < /source | cat > /sink\r\ncat /sink\r\necho APPEND_ARTIFACT >> /sink\r\ncat /sink\r\nsleep 0.1 &\r\njobs\r\nfg\r\necho JOB_CONTROL_ARTIFACT\r\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_xenith-emu"))
        .current_dir(&root)
        .arg("--kernel")
        .arg(&kernel)
        .arg("--initrd")
        .arg(&initrd)
        .arg("--memory")
        .arg("512M")
        .arg("--serial")
        .arg("stdio")
        .arg("--input-script")
        .arg(&script)
        .arg("--max-instructions")
        .arg("180000000")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let _ = fs::remove_file(&script);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Xenith shell 0.1 (type 'help')"),
        "shell did not start:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.matches("PIPE_ARTIFACT").count() >= 2,
        "pipeline/redirection artifact was not read back:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.matches("APPEND_ARTIFACT").count() >= 2,
        "append redirection artifact was not read back:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Running pgid"),
        "background job was not listed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.matches("JOB_CONTROL_ARTIFACT").count() >= 2,
        "foreground job did not return control to the shell:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("errno"),
        "shell reported a syscall failure:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("guest fault"),
        "guest faulted:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

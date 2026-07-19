fn main() {
    if let Err(error) = run() {
        eprintln!("xenith-fsck: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: xenith-fsck IMAGE")?;
    let image = std::fs::read(&path)?;
    let report = xenith_fsck::check(&image)?;
    println!(
        "{}: clean; {} blocks, {} allocated",
        report.filesystem, report.blocks, report.allocated_blocks
    );
    for warning in report.warnings {
        println!("warning: {warning}");
    }
    Ok(())
}

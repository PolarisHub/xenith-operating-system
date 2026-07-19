[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$bootloaderRoot = $PSScriptRoot
$artifactDirectory = Join-Path $bootloaderRoot 'build'
New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null

$hostLine = rustc -vV | Where-Object { $_ -like 'host:*' } | Select-Object -First 1
if (-not $hostLine) {
    throw 'rustc did not report a host target'
}
$hostTarget = ($hostLine -split '\s+', 2)[1]

$stage1Manifest = Join-Path $bootloaderRoot 'stage1\Cargo.toml'
$stage1Binary = Join-Path $artifactDirectory 'stage1.bin'
cargo run --quiet --manifest-path $stage1Manifest --target $hostTarget --release -- --output $stage1Binary

$stage2Manifest = Join-Path $bootloaderRoot 'stage2\Cargo.toml'
cargo build --quiet --manifest-path $stage2Manifest --target x86_64-unknown-none --release --features bios-bin --bin xenith-stage2
$stage2ElfSource = Join-Path $bootloaderRoot 'stage2\target\x86_64-unknown-none\release\xenith-stage2'
$stage2Elf = Join-Path $artifactDirectory 'stage2.elf'
$stage2Binary = Join-Path $artifactDirectory 'stage2.bin'
Copy-Item -LiteralPath $stage2ElfSource -Destination $stage2Elf -Force
cargo run --quiet --manifest-path $stage2Manifest --target $hostTarget --release --features host-tool --bin xenith-stage2-pack -- $stage2Elf $stage2Binary

$uefiManifest = Join-Path $bootloaderRoot 'uefi\Cargo.toml'
cargo build --quiet --manifest-path $uefiManifest --target x86_64-unknown-uefi --release --features uefi-app --bin xenith-bootx64
$uefiSource = Join-Path $bootloaderRoot 'uefi\target\x86_64-unknown-uefi\release\xenith-bootx64.efi'
$uefiBinary = Join-Path $artifactDirectory 'BOOTX64.EFI'
Copy-Item -LiteralPath $uefiSource -Destination $uefiBinary -Force

$stage1Bytes = [System.IO.File]::ReadAllBytes($stage1Binary)
if ($stage1Bytes.Length -ne 512 -or $stage1Bytes[510] -ne 0x55 -or $stage1Bytes[511] -ne 0xaa) {
    throw 'stage1 is not an exact signed 512-byte boot sector'
}
$stage2Length = (Get-Item -LiteralPath $stage2Binary).Length
if ($stage2Length -eq 0 -or $stage2Length % 512 -ne 0 -or $stage2Length -gt 127 * 512) {
    throw 'stage2 violates the BIOS EDD transfer bound'
}
$uefiBytes = [System.IO.File]::ReadAllBytes($uefiBinary)
if ($uefiBytes.Length -lt 256 -or $uefiBytes[0] -ne 0x4d -or $uefiBytes[1] -ne 0x5a) {
    throw 'UEFI artifact is not a PE image'
}
$peOffset = [BitConverter]::ToInt32($uefiBytes, 0x3c)
if ([BitConverter]::ToUInt32($uefiBytes, $peOffset) -ne 0x00004550 -or
    [BitConverter]::ToUInt16($uefiBytes, $peOffset + 4) -ne 0x8664 -or
    [BitConverter]::ToUInt16($uefiBytes, $peOffset + 24) -ne 0x020b -or
    [BitConverter]::ToUInt16($uefiBytes, $peOffset + 24 + 68) -ne 10) {
    throw 'UEFI artifact is not an x86_64 EFI application'
}

@($stage1Binary, $stage2Elf, $stage2Binary, $uefiBinary) | Get-Item | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    '{0,-14} {1,8} bytes  sha256:{2}' -f $_.Name, $_.Length, $hash
}

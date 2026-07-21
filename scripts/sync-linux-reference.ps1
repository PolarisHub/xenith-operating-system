<#
.SYNOPSIS
Creates or verifies Xenith's pinned Linux reference checkout inside WSL.

.DESCRIPTION
Creates a clean, detached checkout of the official Torvalds Linux repository
inside a named WSL distribution's native ext4 filesystem. The checkout is
pinned to commit b95f03f04d475aa6719d15a636ddf32222d55657.

If the destination already contains a clean checkout from the exact official
remote, the script verifies it and moves it to the pinned commit when needed.
It refuses to alter a dirty checkout, an unexpected repository, or any path on
a Windows-mounted filesystem. Linux source is never copied into the Xenith
repository, and the collision-prone Windows checkout is never accessed.

.PARAMETER Distro
The installed WSL distribution name. Defaults to kali-linux.

.PARAMETER Destination
An absolute Linux path inside the selected distribution. When omitted, the
destination is $HOME/src/linux-reference, where HOME is read from WSL itself.

.EXAMPLE
PS> .\scripts\sync-linux-reference.ps1

Creates or verifies /home/<user>/src/linux-reference in kali-linux and prints
its \\wsl.localhost\kali-linux\... Windows UNC path.

.EXAMPLE
PS> .\scripts\sync-linux-reference.ps1 -Distro Ubuntu-24.04 -Destination /home/me/src/linux-reference

Uses the named distribution and explicit ext4-backed Linux path.

.NOTES
The script requires WSL 2, Git inside the distribution, and network access for
initial creation or when the pinned commit is absent locally.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Distro = 'kali-linux',

    [Parameter()]
    [string]$Destination
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LinuxRemote = 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git'
$LinuxCommit = 'b95f03f04d475aa6719d15a636ddf32222d55657'
$WslExecutable = (Get-Command -Name 'wsl.exe' -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source

function Invoke-WslRaw {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$WslArguments
    )

    $outputLines = @(& $WslExecutable @WslArguments 2>&1)
    $exitCode = $LASTEXITCODE
    $output = ($outputLines | ForEach-Object { [string]$_ }) -join "`n"

    [pscustomobject]@{
        ExitCode = $exitCode
        Output   = $output.TrimEnd()
    }
}

function Invoke-DistroRaw {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    Invoke-WslRaw -WslArguments (@('--distribution', $Distro, '--exec') + $Command)
}

function Invoke-DistroChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $result = Invoke-DistroRaw -Command $Command
    if ($result.ExitCode -ne 0) {
        $detail = if ([string]::IsNullOrWhiteSpace($result.Output)) {
            'no diagnostic output'
        }
        else {
            $result.Output
        }
        throw "$Description failed in WSL distribution '$Distro' (exit $($result.ExitCode)): $detail"
    }

    $result.Output
}

function Invoke-GitRaw {
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Repository,

        [Parameter(Mandatory = $true)]
        [string[]]$GitArguments
    )

    $command = @('/usr/bin/git')
    if (-not [string]::IsNullOrEmpty($Repository)) {
        $command += @('-C', $Repository)
    }
    $command += $GitArguments
    Invoke-DistroRaw -Command $command
}

function Invoke-GitChecked {
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Repository,

        [Parameter(Mandatory = $true)]
        [string[]]$GitArguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $result = Invoke-GitRaw -Repository $Repository -GitArguments $GitArguments
    if ($result.ExitCode -ne 0) {
        $detail = if ([string]::IsNullOrWhiteSpace($result.Output)) {
            'no diagnostic output'
        }
        else {
            $result.Output
        }
        throw "$Description failed (exit $($result.ExitCode)): $detail"
    }

    $result.Output
}

function Test-DistroPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Exists', 'Directory')]
        [string]$Kind
    )

    $testFlag = if ($Kind -eq 'Directory') { '-d' } else { '-e' }
    $result = Invoke-DistroRaw -Command @('/usr/bin/test', $testFlag, $Path)
    if ($result.ExitCode -eq 0) {
        return $true
    }
    if ($result.ExitCode -eq 1) {
        return $false
    }

    throw "Unable to inspect WSL path '$Path' (exit $($result.ExitCode)): $($result.Output)"
}

function Assert-NativeLinuxFileSystem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileSystem = (Invoke-DistroChecked `
            -Command @('/usr/bin/stat', '-f', '-c', '%T', '--', $Path) `
            -Description "Inspecting the filesystem for '$Path'").Trim()

    # WSL reports its ext4 virtual disk as "ext2/ext3" through stat(1).
    if ($fileSystem -notin @('ext2/ext3', 'ext4')) {
        throw "Refusing '$Path': filesystem '$fileSystem' is not WSL's native ext4 filesystem. Do not use /mnt/* or another Windows-backed mount."
    }
}

function Assert-FaithfulGitConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository
    )

    $autoCrlf = Invoke-GitRaw -Repository $Repository -GitArguments @('config', '--get', 'core.autocrlf')
    if ($autoCrlf.ExitCode -notin @(0, 1)) {
        throw "Unable to read core.autocrlf in '$Repository': $($autoCrlf.Output)"
    }
    if ($autoCrlf.ExitCode -eq 0 -and $autoCrlf.Output.Trim() -ne 'false') {
        throw "Refusing '$Repository': core.autocrlf must be false for a faithful Linux checkout."
    }

    $ignoreCase = Invoke-GitRaw -Repository $Repository -GitArguments @('config', '--get', 'core.ignorecase')
    if ($ignoreCase.ExitCode -notin @(0, 1)) {
        throw "Unable to read core.ignorecase in '$Repository': $($ignoreCase.Output)"
    }
    if ($ignoreCase.ExitCode -eq 0 -and $ignoreCase.Output.Trim() -ne 'false') {
        throw "Refusing '$Repository': core.ignorecase must be false for a faithful Linux checkout."
    }
}

function Assert-CleanCheckout {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository
    )

    $status = Invoke-GitChecked `
        -Repository $Repository `
        -GitArguments @('status', '--porcelain=v1', '--untracked-files=all') `
        -Description "Checking whether '$Repository' is clean"

    if (-not [string]::IsNullOrWhiteSpace($status)) {
        throw "Refusing to alter dirty Linux checkout '$Repository'. Commit, stash, or remove its changes first.`n$status"
    }
}

$probe = Invoke-WslRaw -WslArguments @('--distribution', $Distro, '--exec', '/usr/bin/true')
if ($probe.ExitCode -ne 0) {
    throw "WSL distribution '$Distro' is not installed or could not start: $($probe.Output)"
}

Invoke-DistroChecked -Command @('/usr/bin/git', '--version') -Description 'Locating Git' | Out-Null

$wslHome = (Invoke-DistroChecked `
        -Command @('/usr/bin/printenv', 'HOME') `
        -Description 'Reading HOME from WSL').Trim()
if ([string]::IsNullOrWhiteSpace($wslHome) -or -not $wslHome.StartsWith('/')) {
    throw "WSL returned an invalid HOME path: '$wslHome'"
}

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = "$($wslHome.TrimEnd('/'))/src/linux-reference"
}
if (-not $Destination.StartsWith('/') -or $Destination -match "[`r`n]") {
    throw "Destination must be one absolute, single-line Linux path; received '$Destination'."
}

$Destination = (Invoke-DistroChecked `
        -Command @('/usr/bin/readlink', '-m', '--', $Destination) `
        -Description 'Canonicalizing the destination path').Trim()
if ($Destination -eq '/' -or $Destination -eq '/mnt' -or $Destination.StartsWith('/mnt/') -or
    $Destination -eq '/run/desktop/mnt/host' -or $Destination.StartsWith('/run/desktop/mnt/host/')) {
    throw "Refusing destination '$Destination'. The Linux checkout must remain inside the distribution's native ext4 filesystem."
}

$lastSlash = $Destination.LastIndexOf('/')
if ($lastSlash -lt 0 -or $lastSlash -eq ($Destination.Length - 1)) {
    throw "Destination '$Destination' does not name a checkout directory."
}
$parentDirectory = if ($lastSlash -eq 0) { '/' } else { $Destination.Substring(0, $lastSlash) }

$destinationExists = Test-DistroPath -Path $Destination -Kind Exists
if ($destinationExists) {
    if (-not (Test-DistroPath -Path $Destination -Kind Directory)) {
        throw "Destination '$Destination' exists but is not a directory."
    }

    Assert-NativeLinuxFileSystem -Path $Destination

    $insideWorkTree = Invoke-GitRaw -Repository $Destination -GitArguments @('rev-parse', '--is-inside-work-tree')
    if ($insideWorkTree.ExitCode -ne 0 -or $insideWorkTree.Output.Trim() -ne 'true') {
        throw "Destination '$Destination' exists but is not a Git working tree; refusing to overwrite it."
    }

    Assert-CleanCheckout -Repository $Destination
    Assert-FaithfulGitConfiguration -Repository $Destination

    $originUrl = (Invoke-GitChecked `
            -Repository $Destination `
            -GitArguments @('remote', 'get-url', 'origin') `
            -Description 'Reading the Linux origin URL').Trim()
    if ($originUrl -cne $LinuxRemote) {
        throw "Refusing checkout '$Destination': origin is '$originUrl', expected exact official remote '$LinuxRemote'."
    }

    $head = (Invoke-GitChecked `
            -Repository $Destination `
            -GitArguments @('rev-parse', 'HEAD') `
            -Description 'Reading the Linux checkout commit').Trim()

    if ($head -cne $LinuxCommit) {
        Invoke-GitChecked `
            -Repository $Destination `
            -GitArguments @('fetch', '--no-tags', '--depth=1', '--filter=blob:none', 'origin', $LinuxCommit) `
            -Description "Fetching pinned Linux commit $LinuxCommit" | Out-Null
        Invoke-GitChecked `
            -Repository $Destination `
            -GitArguments @('-c', 'advice.detachedHead=false', 'checkout', '--detach', $LinuxCommit) `
            -Description "Checking out pinned Linux commit $LinuxCommit" | Out-Null
    }
}
else {
    Invoke-DistroChecked `
        -Command @('/usr/bin/mkdir', '-p', '--', $parentDirectory) `
        -Description "Creating destination parent '$parentDirectory'" | Out-Null
    Assert-NativeLinuxFileSystem -Path $parentDirectory

    $stageName = '.xenith-linux-sync-' + [guid]::NewGuid().ToString('N')
    $stagePath = if ($parentDirectory -eq '/') { "/$stageName" } else { "$parentDirectory/$stageName" }
    $stageCreated = $false
    $stageMoved = $false

    try {
        Invoke-GitChecked `
            -Repository '' `
            -GitArguments @('clone', '--no-checkout', '--filter=blob:none', '--no-tags', '--depth=1', $LinuxRemote, $stagePath) `
            -Description 'Cloning the official Linux repository' | Out-Null
        $stageCreated = $true

        Invoke-GitChecked `
            -Repository $stagePath `
            -GitArguments @('config', 'core.autocrlf', 'false') `
            -Description 'Disabling line-ending conversion' | Out-Null
        Invoke-GitChecked `
            -Repository $stagePath `
            -GitArguments @('config', 'core.ignorecase', 'false') `
            -Description 'Requiring case-sensitive paths' | Out-Null
        Invoke-GitChecked `
            -Repository $stagePath `
            -GitArguments @('fetch', '--no-tags', '--depth=1', '--filter=blob:none', 'origin', $LinuxCommit) `
            -Description "Fetching pinned Linux commit $LinuxCommit" | Out-Null
        Invoke-GitChecked `
            -Repository $stagePath `
            -GitArguments @('-c', 'advice.detachedHead=false', 'checkout', '--detach', $LinuxCommit) `
            -Description "Checking out pinned Linux commit $LinuxCommit" | Out-Null

        Assert-CleanCheckout -Repository $stagePath
        if (Test-DistroPath -Path $Destination -Kind Exists) {
            throw "Destination '$Destination' appeared during synchronization; refusing to overwrite it."
        }

        Invoke-DistroChecked `
            -Command @('/usr/bin/mv', '--', $stagePath, $Destination) `
            -Description "Publishing checkout at '$Destination'" | Out-Null
        $stageMoved = $true
    }
    finally {
        if ($stageCreated -and -not $stageMoved) {
            $expectedPrefix = if ($parentDirectory -eq '/') {
                '/.xenith-linux-sync-'
            }
            else {
                "$parentDirectory/.xenith-linux-sync-"
            }

            if ($stagePath.StartsWith($expectedPrefix, [System.StringComparison]::Ordinal)) {
                $cleanup = Invoke-DistroRaw -Command @(
                    '/usr/bin/rm', '--recursive', '--force', '--one-file-system', '--', $stagePath
                )
                if ($cleanup.ExitCode -ne 0) {
                    Write-Warning "Could not remove incomplete staging checkout '$stagePath': $($cleanup.Output)"
                }
            }
        }
    }
}

Assert-NativeLinuxFileSystem -Path $Destination
Assert-CleanCheckout -Repository $Destination
Assert-FaithfulGitConfiguration -Repository $Destination

$verifiedOrigin = (Invoke-GitChecked `
        -Repository $Destination `
        -GitArguments @('remote', 'get-url', 'origin') `
        -Description 'Verifying the official Linux origin').Trim()
$verifiedCommit = (Invoke-GitChecked `
        -Repository $Destination `
        -GitArguments @('rev-parse', 'HEAD') `
        -Description 'Verifying the pinned Linux commit').Trim()

if ($verifiedOrigin -cne $LinuxRemote) {
    throw "Linux origin verification failed: expected '$LinuxRemote', received '$verifiedOrigin'."
}
if ($verifiedCommit -cne $LinuxCommit) {
    throw "Linux commit verification failed: expected '$LinuxCommit', received '$verifiedCommit'."
}

$uncSuffix = $Destination.Replace('/', '\')
$uncPath = "\\wsl.localhost\$Distro$uncSuffix"
Write-Output $uncPath

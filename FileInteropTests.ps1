param(
    [string]$BlockedBasePath = "C:\Temp\HostGuardInterop",
    [string]$GeneralSysPath = "C:\Temp\HostGuardAny\global_block.sys"
)

$ErrorActionPreference = "Stop"

function Invoke-ExpectBlocked {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "==== $Name ===="
    try {
        & $Action
        Write-Host "[UNEXPECTED] operation succeeded"
    }
    catch {
        Write-Host "[BLOCKED] $($_.Exception.Message)"
    }
    Write-Host
}

function Invoke-ExpectAllowed {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "==== $Name ===="
    try {
        & $Action
        Write-Host "[ALLOWED] completed successfully"
    }
    catch {
        Write-Host "[UNEXPECTED] operation failed: $($_.Exception.Message)"
    }
    Write-Host
}

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-IfExists {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue
    }
}

$blockedDirParent = Split-Path -Path $BlockedBasePath -Parent
$generalSysParent = Split-Path -Path $GeneralSysPath -Parent

Ensure-Directory -Path $blockedDirParent
Ensure-Directory -Path $generalSysParent
Ensure-Directory -Path $BlockedBasePath

Remove-IfExists -Path "$BlockedBasePath\allowed.txt"
Remove-IfExists -Path "$BlockedBasePath\blocked_from_pwsh.exe"
Remove-IfExists -Path "$BlockedBasePath\blocked_from_pwsh.dll"
Remove-IfExists -Path "$BlockedBasePath\blocked_from_pwsh.sys"
Remove-IfExists -Path "$BlockedBasePath\blocked_from_cmd.exe"
Remove-IfExists -Path $GeneralSysPath

Invoke-ExpectAllowed "allowed_txt_from_powershell" {
    Set-Content -LiteralPath "$BlockedBasePath\allowed.txt" -Value "safe-text" -Encoding ASCII -Force
}

Invoke-ExpectBlocked "blocked_sys_anywhere_from_powershell" {
    Set-Content -LiteralPath $GeneralSysPath -Value "fake-sys" -Encoding ASCII -Force
}

Invoke-ExpectBlocked "blocked_exe_from_powershell_in_interop_dir" {
    Set-Content -LiteralPath "$BlockedBasePath\blocked_from_pwsh.exe" -Value "fake-exe" -Encoding ASCII -Force
}

Invoke-ExpectBlocked "blocked_dll_from_powershell_in_interop_dir" {
    Set-Content -LiteralPath "$BlockedBasePath\blocked_from_pwsh.dll" -Value "fake-dll" -Encoding ASCII -Force
}

Invoke-ExpectBlocked "blocked_sys_from_powershell_in_interop_dir" {
    Set-Content -LiteralPath "$BlockedBasePath\blocked_from_pwsh.sys" -Value "fake-sys" -Encoding ASCII -Force
}

Invoke-ExpectBlocked "blocked_exe_from_cmd_in_interop_dir" {
    cmd.exe /c "echo fake-cmd-exe> `"$BlockedBasePath\blocked_from_cmd.exe`""
    if ($LASTEXITCODE -ne 0) {
        throw "cmd exit code $LASTEXITCODE"
    }
    if (Test-Path -LiteralPath "$BlockedBasePath\blocked_from_cmd.exe") {
        throw "cmd.exe created the file unexpectedly"
    }
}

Write-Host "File interop test sequence finished."

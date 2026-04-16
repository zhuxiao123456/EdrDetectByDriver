param(
    [string]$BasePath = "HKCU:\Software\HostGuardInterop"
)

$ErrorActionPreference = "Stop"

$baseRelativePath = $BasePath -replace '^HKCU:\\', ''

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class NativeRegistryInterop
{
    public const int KEY_ALL_ACCESS = 0xF003F;
    public const int KeyWriteTimeInformation = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegOpenKeyEx(
        UIntPtr hKey,
        string lpSubKey,
        int ulOptions,
        int samDesired,
        out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegRenameKey(
        IntPtr hKey,
        string lpSubKeyName,
        string lpNewKeyName);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);

    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationKey(
        IntPtr KeyHandle,
        int KeySetInformationClass,
        ref long KeySetInformation,
        int KeySetInformationLength);
}
"@

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "==== $Name ===="
    try {
        & $Action
        Write-Host "[RESULT] completed without block"
    }
    catch {
        Write-Host "[RESULT] blocked or failed: $($_.Exception.Message)"
    }
    Write-Host
}

function Ensure-Key {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Remove-KeyIfExists {
    param([string]$Path)

    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Remove-KeyIfExists -Path $BasePath
Ensure-Key -Path $BasePath

Invoke-Step "create_key" {
    New-Item -Path "$BasePath\CreateKeyBlocked" -Force | Out-Null
}

Ensure-Key -Path "$BasePath\SetValueTarget"
Invoke-Step "set_value" {
    New-ItemProperty -Path "$BasePath\SetValueTarget" -Name "DangerValue" -Value "blocked" -PropertyType String -Force | Out-Null
}

Ensure-Key -Path "$BasePath\DeleteValueTarget"
New-ItemProperty -Path "$BasePath\DeleteValueTarget" -Name "DangerValue" -Value "delete-me" -PropertyType String -Force | Out-Null
Invoke-Step "delete_value" {
    Remove-ItemProperty -Path "$BasePath\DeleteValueTarget" -Name "DangerValue" -Force
}

Ensure-Key -Path "$BasePath\DeleteKeyTarget"
Invoke-Step "delete_key" {
    Remove-Item -Path "$BasePath\DeleteKeyTarget" -Recurse -Force
}

Ensure-Key -Path "$BasePath\RenameSource"
Invoke-Step "rename_key" {
    $hkcu = [UIntPtr]0x80000001
    $rc = [NativeRegistryInterop]::RegRenameKey([IntPtr]$hkcu, $baseRelativePath + "\RenameSource", "RenameBlocked")
    if ($rc -ne 0) {
        throw "RegRenameKey failed with error code $rc"
    }
}

Ensure-Key -Path "$BasePath\SetInformationTarget"
Invoke-Step "set_information_key" {
    $hkcu = [UIntPtr]0x80000001
    $handle = [IntPtr]::Zero
    $rc = [NativeRegistryInterop]::RegOpenKeyEx($hkcu, $baseRelativePath + "\SetInformationTarget", 0, [NativeRegistryInterop]::KEY_ALL_ACCESS, [ref]$handle)
    if ($rc -ne 0) {
        throw "RegOpenKeyEx failed with error code $rc"
    }

    try {
        $timestamp = [DateTime]::UtcNow.ToFileTimeUtc()
        $status = [NativeRegistryInterop]::NtSetInformationKey($handle, [NativeRegistryInterop]::KeyWriteTimeInformation, [ref]$timestamp, 8)
        if ($status -ne 0) {
            $hex = ('0x{0:X8}' -f ($status -band 0xFFFFFFFFL))
            throw "NtSetInformationKey failed with NTSTATUS $hex"
        }
    }
    finally {
        [void][NativeRegistryInterop]::RegCloseKey($handle)
    }
}

Write-Host "Registry interop test sequence finished."

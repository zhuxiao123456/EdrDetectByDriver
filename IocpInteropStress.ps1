param(
    [string]$HostGuardExe = ".\HostGuard.exe",
    [string]$RulesTemplate = ".\iocp_stress_rules.json",
    [string]$DriverServiceName = "PebMonitor",
    [int]$BurstRounds = 12,
    [int]$BurstWidth = 20,
    [int]$ReconnectPauseSec = 4,
    [string]$OutputDir = ".\stress_output",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Invoke-DriverServiceAction([string]$Action, [string]$ServiceName) {
    $proc = Start-Process -FilePath sc.exe -ArgumentList @($Action, $ServiceName) -PassThru -Wait -NoNewWindow
    return $proc.ExitCode
}

function Invoke-StressBurst([string]$PhaseTag, [int]$Rounds, [int]$Width, [string]$StressDir) {
    Write-Host "[*] Burst start: phase=$PhaseTag rounds=$Rounds width=$Width"
    for ($r = 0; $r -lt $Rounds; $r++) {
        for ($i = 0; $i -lt $Width; $i++) {
            $seq = ($r * $Width) + $i
            $token = "HGSTRESS_BLOCK_$seq"

            Start-Process -FilePath powershell.exe `
                -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Write-Output '$token'") `
                -WindowStyle Hidden | Out-Null

            $filePath = Join-Path $StressDir ("drop_{0}_{1}.sys" -f $PhaseTag, $seq)
            try {
                Set-Content -LiteralPath $filePath -Value $token -Force -Encoding ascii
            }
            catch {
            }

            try {
                New-Item -Path "HKCU:\Software\HostGuardIocpStress\SetValueTarget" -Force | Out-Null
                Set-ItemProperty -Path "HKCU:\Software\HostGuardIocpStress\SetValueTarget" -Name "DangerValue" -Value $token -Force
            }
            catch {
            }

            try {
                New-Item -Path ("HKCU:\Software\HostGuardIocpStress\CreateKeyBlocked\{0}" -f $seq) -Force | Out-Null
            }
            catch {
            }
        }
    }
    Write-Host "[+] Burst done: phase=$PhaseTag"
}

function Find-EventsJsonl([string]$ExeDir) {
    $candidates = @(
        (Join-Path $ExeDir "events.jsonl"),
        (Join-Path $env:ProgramData "HostGuard\events.jsonl")
    )
    foreach ($p in $candidates) {
        if (Test-Path -LiteralPath $p) {
            return $p
        }
    }
    return $null
}

function Summarize-JsonEvents([string]$Path, [datetime]$StartTime) {
    $result = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $result
    }

    $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $obj = $line | ConvertFrom-Json -ErrorAction Stop
            if ($obj.timestamp) {
                $ts = [datetime]::Parse($obj.timestamp.ToString())
                if ($ts -lt $StartTime) { continue }
            }
            $eventType = ""
            if ($obj.event_type) {
                $eventType = $obj.event_type.ToString()
            }
            elseif ($obj.type) {
                $eventType = $obj.type.ToString()
            }
            else {
                $eventType = "<unknown>"
            }

            if (-not $result.Contains($eventType)) {
                $result[$eventType] = 0
            }
            $result[$eventType] += 1
        }
        catch {
        }
    }
    return $result
}

if (-not $DryRun -and -not (Test-IsAdmin)) {
    throw "Please run this script as Administrator."
}

$hostGuardExePath = (Resolve-Path -LiteralPath $HostGuardExe).Path
$rulesTemplatePath = (Resolve-Path -LiteralPath $RulesTemplate).Path
$exeDir = Split-Path -Parent $hostGuardExePath
$rulesPath = Join-Path $exeDir "rules.json"
$stdoutLog = Join-Path $OutputDir "hostguard_stdout.log"
$stderrLog = Join-Path $OutputDir "hostguard_stderr.log"
$reportPath = Join-Path $OutputDir "iocp_stress_report.txt"
$stressDir = Join-Path $env:TEMP "HostGuardIocpStress"
$backupRulesPath = "$rulesPath.bak.stress"
$hostGuardProc = $null
$startAt = Get-Date

Ensure-Dir $OutputDir
Ensure-Dir $stressDir

Write-Host "[*] HostGuard exe: $hostGuardExePath"
Write-Host "[*] Rules template: $rulesTemplatePath"
Write-Host "[*] Runtime rules: $rulesPath"
Write-Host "[*] Output dir: $OutputDir"

if ($DryRun) {
    Write-Host "[+] DryRun only. Environment check passed."
    exit 0
}

if (Test-Path -LiteralPath $backupRulesPath) {
    Remove-Item -LiteralPath $backupRulesPath -Force
}

if (Test-Path -LiteralPath $rulesPath) {
    Copy-Item -LiteralPath $rulesPath -Destination $backupRulesPath -Force
}

Copy-Item -LiteralPath $rulesTemplatePath -Destination $rulesPath -Force

if (Test-Path -LiteralPath $stdoutLog) { Remove-Item -LiteralPath $stdoutLog -Force }
if (Test-Path -LiteralPath $stderrLog) { Remove-Item -LiteralPath $stderrLog -Force }

try {
    $hostGuardProc = Start-Process -FilePath $hostGuardExePath `
        -WorkingDirectory $exeDir `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog

    Write-Host "[+] HostGuard started, pid=$($hostGuardProc.Id)"
    Start-Sleep -Seconds 5

    Invoke-StressBurst -PhaseTag "phase1" -Rounds $BurstRounds -Width $BurstWidth -StressDir $stressDir

    Write-Host "[*] Trigger driver disconnect/reconnect..."
    [void](Invoke-DriverServiceAction -Action "stop" -ServiceName $DriverServiceName)
    Start-Sleep -Seconds $ReconnectPauseSec
    [void](Invoke-DriverServiceAction -Action "start" -ServiceName $DriverServiceName)
    Start-Sleep -Seconds 3

    Invoke-StressBurst -PhaseTag "phase2" -Rounds $BurstRounds -Width $BurstWidth -StressDir $stressDir

    Start-Sleep -Seconds 2
}
finally {
    if ($hostGuardProc -and -not $hostGuardProc.HasExited) {
        Stop-Process -Id $hostGuardProc.Id -Force
        Start-Sleep -Seconds 1
    }

    if (Test-Path -LiteralPath $backupRulesPath) {
        Copy-Item -LiteralPath $backupRulesPath -Destination $rulesPath -Force
        Remove-Item -LiteralPath $backupRulesPath -Force
    }
}

$eventsPath = Find-EventsJsonl -ExeDir $exeDir
$summary = @{}
if ($eventsPath) {
    $summary = Summarize-JsonEvents -Path $eventsPath -StartTime $startAt
}

$stdoutText = ""
if (Test-Path -LiteralPath $stdoutLog) {
    $stdoutText = Get-Content -LiteralPath $stdoutLog -Raw -ErrorAction SilentlyContinue
}

$reconnectSignals = 0
if ($stdoutText) {
    $patterns = @(
        "重连成功",
        "通信端口断开",
        "IOCP",
        "驱动遥测通道连接失败"
    )
    foreach ($p in $patterns) {
        $reconnectSignals += ([regex]::Matches($stdoutText, [regex]::Escape($p))).Count
    }
}

$report = New-Object System.Text.StringBuilder
$eventsPathForReport = "<not found>"
if ($eventsPath) {
    $eventsPathForReport = $eventsPath
}
[void]$report.AppendLine("HostGuard IOCP Interop Stress Report")
[void]$report.AppendLine(("StartTime: {0}" -f $startAt.ToString("s")))
[void]$report.AppendLine(("HostGuardExe: {0}" -f $hostGuardExePath))
[void]$report.AppendLine(("RulesTemplate: {0}" -f $rulesTemplatePath))
[void]$report.AppendLine(("DriverService: {0}" -f $DriverServiceName))
[void]$report.AppendLine(("BurstRounds: {0}" -f $BurstRounds))
[void]$report.AppendLine(("BurstWidth: {0}" -f $BurstWidth))
[void]$report.AppendLine(("EventsPath: {0}" -f $eventsPathForReport))
[void]$report.AppendLine(("ReconnectSignalCount: {0}" -f $reconnectSignals))
[void]$report.AppendLine("")
[void]$report.AppendLine("EventTypeCounts:")

if ($summary.Count -eq 0) {
    [void]$report.AppendLine("  <no parsed events>")
}
else {
    foreach ($k in $summary.Keys | Sort-Object) {
        [void]$report.AppendLine(("  {0}: {1}" -f $k, $summary[$k]))
    }
}

$reportText = $report.ToString()
$reportText | Out-File -LiteralPath $reportPath -Encoding utf8

Write-Host "[+] Stress run finished."
Write-Host "[+] Report: $reportPath"
if ($eventsPath) {
    Write-Host "[+] Events: $eventsPath"
}
Write-Host "[+] StdoutLog: $stdoutLog"
Write-Host "[+] StderrLog: $stderrLog"

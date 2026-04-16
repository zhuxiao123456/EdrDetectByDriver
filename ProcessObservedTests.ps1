param(
    [string]$EventPath = '',
    [int]$TimeoutSeconds = 20,
    [int]$PollIntervalMs = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Resolve-ObservedEventPath {
    param([string]$PreferredPath)

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        return $PreferredPath
    }

    $candidates = @(
        'C:\ProgramData\HostGuard\events.jsonl',
        'C:\ransomware\events.jsonl'
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    if (Test-Path 'C:\ProgramData\HostGuard') {
        return 'C:\ProgramData\HostGuard\events.jsonl'
    }

    return 'C:\ransomware\events.jsonl'
}

function Read-JsonLines {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return @()
    }

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($line in Get-Content $Path -ErrorAction SilentlyContinue) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $normalizedLine = $line
        if ($normalizedLine.Length -gt 0 -and $normalizedLine[0] -eq [char]0xFEFF) {
            $normalizedLine = $normalizedLine.Substring(1)
        }

        try {
            $events.Add(($normalizedLine | ConvertFrom-Json -ErrorAction Stop))
        }
        catch {
        }
    }

    return $events
}

function New-ExpectedLaunch {
    param(
        [string]$ProcessName,
        [string]$Token,
        [System.Diagnostics.Process]$Process
    )

    return [pscustomobject]@{
        ProcessName = $ProcessName
        Token = $Token
        Process = $Process
        ProcessId = $Process.Id
        Event = $null
    }
}

function Find-ObservedEvent {
    param(
        [object[]]$Events,
        [object]$Expected
    )

    foreach ($event in $Events) {
        if ($null -eq $event) {
            continue
        }

        if ($event.event_type -ne 'observed_process_create') {
            continue
        }

        if ($event.driver_event_name -ne 'observed_process_create') {
            continue
        }

        $eventProcessId = 0
        try {
            $eventProcessId = [int]$event.process_id
        }
        catch {
            $eventProcessId = 0
        }

        $eventProcessName = [string]$event.process_name
        $eventCommandLine = [string]$event.command_line
        $eventImagePath = [string]$event.image_path

        $pidMatched = ($eventProcessId -eq $Expected.ProcessId)
        $nameMatched = $false
        if (-not [string]::IsNullOrWhiteSpace($eventProcessName)) {
            $nameMatched = $eventProcessName.Equals($Expected.ProcessName, [System.StringComparison]::OrdinalIgnoreCase)
        }

        $tokenMatched = $false
        if (-not [string]::IsNullOrWhiteSpace($Expected.Token)) {
            $tokenMatched =
                (($eventCommandLine -like ('*' + $Expected.Token + '*')) -or
                 ($eventImagePath -like ('*' + $Expected.Token + '*')))
        }

        if (($pidMatched -and $nameMatched) -or ($nameMatched -and $tokenMatched) -or $pidMatched) {
            return $event
        }
    }

    return $null
}

$resolvedEventPath = Resolve-ObservedEventPath -PreferredPath $EventPath
Write-Step "Using event log path: $resolvedEventPath"

$tempRoot = Join-Path $env:TEMP ('HostGuardObserved-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

$baseToken = 'HGOBS-' + (Get-Date -Format 'yyyyMMddHHmmssfff')
$startedProcesses = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
$expectedLaunches = New-Object System.Collections.Generic.List[object]

try {
    $cmdToken = $baseToken + '-CMD'
    $cmdArgs = '/c "echo ' + $cmdToken + ' > NUL & ping -n 2 127.0.0.1 > NUL"'
    $cmdProcess = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList $cmdArgs -PassThru -WindowStyle Hidden
    $startedProcesses.Add($cmdProcess)
    $expectedLaunches.Add((New-ExpectedLaunch -ProcessName 'cmd.exe' -Token $cmdToken -Process $cmdProcess))
    Write-Step ("Started cmd.exe for observed telemetry test. PID={0} Token={1}" -f $cmdProcess.Id, $cmdToken)

    $psToken = $baseToken + '-PS'
    $psArgs = '-NoProfile -ExecutionPolicy Bypass -Command "$env:HGOBS_TOKEN=''' + $psToken + '''; Start-Sleep -Milliseconds 900"'
    $psProcess = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $psArgs -PassThru -WindowStyle Hidden
    $startedProcesses.Add($psProcess)
    $expectedLaunches.Add((New-ExpectedLaunch -ProcessName 'powershell.exe' -Token $psToken -Process $psProcess))
    Write-Step ("Started powershell.exe for observed telemetry test. PID={0} Token={1}" -f $psProcess.Id, $psToken)

    $wscriptToken = $baseToken + '-WS'
    $vbsPath = Join-Path $tempRoot ('observed-' + $wscriptToken + '.vbs')
    Set-Content -Path $vbsPath -Value 'WScript.Sleep 900' -Encoding ASCII
    $wscriptArgs = '//NoLogo "' + $vbsPath + '"'
    $wscriptProcess = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\wscript.exe') -ArgumentList $wscriptArgs -PassThru -WindowStyle Hidden
    $startedProcesses.Add($wscriptProcess)
    $expectedLaunches.Add((New-ExpectedLaunch -ProcessName 'wscript.exe' -Token $wscriptToken -Process $wscriptProcess))
    Write-Step ("Started wscript.exe for observed telemetry test. PID={0} Token={1}" -f $wscriptProcess.Id, $wscriptToken)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $events = Read-JsonLines -Path $resolvedEventPath
        foreach ($expected in $expectedLaunches) {
            if ($null -ne $expected.Event) {
                continue
            }

            $match = Find-ObservedEvent -Events $events -Expected $expected
            if ($null -ne $match) {
                $expected.Event = $match
            }
        }

        $pending = @($expectedLaunches | Where-Object { $null -eq $_.Event })
        if ($pending.Count -eq 0) {
            break
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    $missing = @($expectedLaunches | Where-Object { $null -eq $_.Event })
    if ($missing.Count -gt 0) {
        Write-Host ''
        Write-Host '[!] Missing observed_process_create events for:' -ForegroundColor Yellow
        $missing | ForEach-Object {
            Write-Host ("    {0} (PID={1}, Token={2})" -f $_.ProcessName, $_.ProcessId, $_.Token) -ForegroundColor Yellow
        }

        $recentObserved = Read-JsonLines -Path $resolvedEventPath |
            Where-Object { $_.event_type -eq 'observed_process_create' } |
            Select-Object -Last 10

        if ($recentObserved.Count -gt 0) {
            Write-Host ''
            Write-Host '[*] Recent observed_process_create events:' -ForegroundColor Cyan
            $recentObserved |
                Select-Object time, process_id, parent_process_id, process_name, image_path, command_line |
                Format-Table -AutoSize
        }

        throw 'Observed process telemetry validation failed.'
    }

    $results = foreach ($expected in $expectedLaunches) {
        [pscustomobject]@{
            ProcessName = $expected.ProcessName
            ProcessId = $expected.ProcessId
            ParentProcessId = [int]$expected.Event.parent_process_id
            ImagePath = [string]$expected.Event.image_path
            CommandLine = [string]$expected.Event.command_line
        }
    }

    Write-Host ''
    Write-Success 'Observed process telemetry validated successfully.'
    $results | Format-Table -AutoSize
}
finally {
    foreach ($process in $startedProcesses) {
        if ($null -eq $process) {
            continue
        }

        try {
            if (-not $process.HasExited) {
                Wait-Process -Id $process.Id -Timeout 3 -ErrorAction Stop
            }
        }
        catch {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }

    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

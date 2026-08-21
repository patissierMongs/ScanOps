[CmdletBinding()]
param(
    [ValidateSet('start', 'status', 'check', 'list', 'stop', 'foreground')]
    [string]$Action = 'start'
)

$ErrorActionPreference = 'Stop'
$labScript = Join-Path $PSScriptRoot 'loopback_lab.py'
$runtimeDir = Join-Path $PSScriptRoot '.loopback_lab'
$stateFile = Join-Path $runtimeDir 'state.json'
$stopFile = Join-Path $runtimeDir 'stop.request'
$stdoutLog = Join-Path $runtimeDir 'stdout.log'
$stderrLog = Join-Path $runtimeDir 'stderr.log'

function Resolve-Python {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\backend\.venv\Scripts\python.exe'),
        (Join-Path $PSScriptRoot '..\python\python.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    $launcher = Get-Command 'py.exe' -ErrorAction SilentlyContinue
    if ($null -ne $launcher) {
        $resolved = & $launcher.Source -3 -c 'import sys; print(sys.executable)'
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $resolved).Path
        }
    }

    $python = Get-Command 'python.exe' -ErrorAction SilentlyContinue
    if ($null -ne $python) {
        return $python.Source
    }
    throw 'Python 3 was not found. Install Python or run this from the ScanOps all-in-one directory.'
}

function Read-LabState {
    if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
        return $null
    }
    try {
        return (Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Get-LabProcess {
    $state = Read-LabState
    if ($null -eq $state -or $null -eq $state.pid) {
        return $null
    }
    $process = Get-Process -Id ([int]$state.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $null
    }
    $details = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $process.Id) -ErrorAction SilentlyContinue
    if ($null -eq $details -or $details.CommandLine -notlike '*loopback_lab.py*') {
        return $null
    }
    return $process
}

function Show-Status {
    $state = Read-LabState
    $process = Get-LabProcess
    if ($null -eq $state -or $null -eq $process) {
        Write-Host 'Loopback lab: stopped'
        return $false
    }
    Write-Host ("Loopback lab: running (PID {0}, target {1})" -f $state.pid, $state.target)
    foreach ($hostEntry in $state.hosts) {
        Write-Host ("  {0} {1}: TCP {2} / UDP {3}" -f $hostEntry.ip, $hostEntry.name, ($hostEntry.tcp -join ','), ($hostEntry.udp -join ','))
    }
    return $true
}

$pythonExe = Resolve-Python

switch ($Action) {
    'list' {
        & $pythonExe $labScript --list
        exit $LASTEXITCODE
    }
    'foreground' {
        & $pythonExe $labScript
        exit $LASTEXITCODE
    }
    'status' {
        if (Show-Status) { exit 0 } else { exit 1 }
    }
    'check' {
        & $pythonExe $labScript --check
        exit $LASTEXITCODE
    }
    'stop' {
        $process = Get-LabProcess
        if ($null -eq $process) {
            Write-Host 'Loopback lab is already stopped.'
            exit 0
        }
        New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
        Set-Content -LiteralPath $stopFile -Value 'stop' -Encoding ASCII
        try {
            Wait-Process -Id $process.Id -Timeout 10 -ErrorAction Stop
        }
        catch {
            $process = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
            if ($null -ne $process) {
                Stop-Process -Id $process.Id -Force
            }
        }
        Write-Host 'Loopback lab stopped.'
        exit 0
    }
    'start' {
        if ($null -ne (Get-LabProcess)) {
            Write-Host 'Loopback lab is already running.'
            Show-Status | Out-Null
            exit 0
        }
        New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
        Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stopFile -Force -ErrorAction SilentlyContinue
        $arguments = @(
            '-X', 'utf8',
            ('"{0}"' -f $labScript),
            '--state-file', ('"{0}"' -f $stateFile),
            '--stop-file', ('"{0}"' -f $stopFile)
        )
        $process = Start-Process -FilePath $pythonExe -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            if ($process.HasExited) {
                $detail = ''
                if (Test-Path -LiteralPath $stderrLog) {
                    $detail = Get-Content -LiteralPath $stderrLog -Raw -Encoding UTF8
                }
                throw "Loopback lab exited before it became ready. $detail"
            }
            if ($null -ne (Read-LabState)) {
                Write-Host 'Loopback lab started.'
                Show-Status | Out-Null
                exit 0
            }
            Start-Sleep -Milliseconds 100
            $process.Refresh()
        }
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'Loopback lab did not become ready within 10 seconds.'
    }
}

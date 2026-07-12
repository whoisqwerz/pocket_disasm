[CmdletBinding()]
param(
    [string]$Source = "",
    [string]$IdaDir = "",
    [switch]$NoLaunch,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ProductRoot = Join-Path $env:LOCALAPPDATA "PocketDisasm"
$VenvRoot = Join-Path $ProductRoot "venv"
$BinRoot = Join-Path $ProductRoot "bin"
$PythonExe = Join-Path $VenvRoot "Scripts\python.exe"

function Write-Step([string]$Message) {
    Write-Host "  ~ " -NoNewline -ForegroundColor Cyan
    Write-Host $Message
}

function Update-UserPath([string]$Directory, [bool]$Add) {
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($current -split ";" | Where-Object { $_ -and $_ -ne $Directory })
    if ($Add) { $parts += $Directory }
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
}

function Find-Python {
    $commands = @(
        @{ Exe = "py"; Args = @("-3.12") },
        @{ Exe = "py"; Args = @("-3.11") },
        @{ Exe = "python"; Args = @() }
    )
    foreach ($candidate in $commands) {
        try {
            $arguments = $candidate.Args
            $path = & $candidate.Exe @arguments -c "import sys; print(sys.executable if sys.version_info >= (3,11) else '')" 2>$null
            if ($LASTEXITCODE -eq 0 -and $path) { return $path.Trim() }
        } catch { }
    }
    return $null
}

if ($Uninstall) {
    Write-Step "Stopping Pocket Disasm"
    if (Test-Path $PythonExe) {
        & $PythonExe -m pocket_disasm stop 2>$null | Out-Null
    }
    Update-UserPath $BinRoot $false
    if (Test-Path $VenvRoot) { Remove-Item -LiteralPath $VenvRoot -Recurse -Force }
    if (Test-Path $BinRoot) { Remove-Item -LiteralPath $BinRoot -Recurse -Force }
    Write-Host "Pocket Disasm was removed. Open a new terminal to refresh PATH."
    exit 0
}

if (-not $Source) {
    if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "pyproject.toml"))) {
        $Source = $PSScriptRoot
    } elseif ($env:POCKET_DISASM_SOURCE) {
        $Source = $env:POCKET_DISASM_SOURCE
    } else {
        $Source = "https://github.com/whoisqwerz/pocket_disasm/archive/refs/heads/main.zip"
    }
}

$BootstrapPython = Find-Python
if (-not $BootstrapPython) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw "Python 3.11+ was not found and winget is unavailable. Install Python 3.12, then run this command again."
    }
    Write-Step "Installing Python 3.12 for the current user"
    & winget.exe install --id Python.Python.3.12 --exact --scope user --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw "Python installation failed with exit code $LASTEXITCODE." }
    $BootstrapPython = Find-Python
    if (-not $BootstrapPython) { throw "Python was installed but could not be located. Open a new terminal and run install.ps1 again." }
}

New-Item -ItemType Directory -Force -Path $ProductRoot, $BinRoot | Out-Null
if (-not (Test-Path $PythonExe)) {
    Write-Step "Creating an isolated Python environment"
    & $BootstrapPython -m venv $VenvRoot
    if ($LASTEXITCODE -ne 0) { throw "Could not create the Pocket Disasm environment." }
}

Write-Step "Installing Pocket Disasm and its pinned dependencies"
& $PythonExe -m pip install --disable-pip-version-check --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) { throw "Could not update the Python packaging tools." }
& $PythonExe -m pip install --disable-pip-version-check --upgrade $Source
if ($LASTEXITCODE -ne 0) { throw "Pocket Disasm installation failed." }

$Shim = @"
@echo off
setlocal
if "%~1"=="" (
  "%LOCALAPPDATA%\PocketDisasm\venv\Scripts\python.exe" -m pocket_disasm control
) else (
  "%LOCALAPPDATA%\PocketDisasm\venv\Scripts\python.exe" -m pocket_disasm %*
)
exit /b %errorlevel%
"@
Set-Content -LiteralPath (Join-Path $BinRoot "pocket.cmd") -Value $Shim -Encoding Ascii
Set-Content -LiteralPath (Join-Path $BinRoot "pocket-disasm.cmd") -Value $Shim -Encoding Ascii
Update-UserPath $BinRoot $true
$env:Path = "$BinRoot;$env:Path"

if ($IdaDir) {
    Write-Step "Saving the IDA installation"
    & $PythonExe -m pocket_disasm config --ida-dir $IdaDir
    if ($LASTEXITCODE -ne 0) { throw "The selected directory does not contain IDALib." }
}

Write-Step "Running diagnostics"
& $PythonExe -m pocket_disasm doctor
$DoctorExit = $LASTEXITCODE

Write-Host ""
Write-Host "Pocket Disasm is installed." -ForegroundColor Green
Write-Host "Command:  pocket"
Write-Host "Location: $ProductRoot"
Write-Host ""
if ($DoctorExit -ne 0) {
    Write-Host "IDA still needs configuration. Run: pocket" -ForegroundColor Yellow
}
Write-Host "Open a new terminal before using the global command there."

if (-not $NoLaunch) {
    & $PythonExe -m pocket_disasm control
}

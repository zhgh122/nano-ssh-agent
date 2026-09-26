# One-shot setup of Nano SSH Agent on Windows: fetch the build + host files from the
# Linux machine that built them (the "build host"), load the app on the Nano S Plus,
# start the agent, authorize the device key on that host and test the login.
#
# Usage (PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -Target user@buildhost
#   powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -Target user@buildhost -Port 2222 -Key $HOME\.ssh\id_rsa
#
# Options:
#   -Target      user@host of the build host (asked if omitted)
#   -Port        its SSH port (default 22, asked if omitted)
#   -RemoteDir   repository path on the build host, relative to the home (default nano-ssh-agent, asked if omitted)
#   -Key         private key you already use for that host (auto-detected if omitted)
#   -SkipLoad    do not (re)install the app on the device
#
# ASCII only on purpose: Windows PowerShell 5.1 misreads UTF-8 files without BOM.

param(
    [string]$Target = "",
    [int]$Port = 22,
    [string]$RemoteDir = "nano-ssh-agent",
    [string]$Key = "",
    [switch]$SkipLoad
)

$ErrorActionPreference = "Stop"

# Ask for what was not given on the command line (e.g. when run with right-click > Run with PowerShell)
function Ask-Default([string]$prompt, [string]$default) {
    $answer = Read-Host "$prompt [$default]"
    if ($answer.Trim() -eq "") { return $default }
    return $answer.Trim()
}
if ($Target -eq "") {
    Write-Host "Server that holds the build (the Linux machine where you ran make), as user@address."
    Write-Host "Example: ubuntu@203.0.113.10"
    $Target = (Read-Host "Server").Trim()
}
if ($Target -notmatch '^[^@\s]+@[^@\s]+$') { Write-Host "ERROR: expected user@address, got '$Target'" -ForegroundColor Red; Read-Host "Press Enter to close" | Out-Null; exit 1 }
if (-not $PSBoundParameters.ContainsKey("Port")) {
    $portText = Ask-Default "SSH port of that server" "$Port"
    if (-not [int]::TryParse($portText, [ref]$Port)) { Write-Host "ERROR: invalid port '$portText'" -ForegroundColor Red; Read-Host "Press Enter to close" | Out-Null; exit 1 }
}
if (-not $PSBoundParameters.ContainsKey("RemoteDir")) {
    $RemoteDir = Ask-Default "Project folder on that server, relative to its home" $RemoteDir
}
$Pipe = "\\.\pipe\nano-ssh-agent"
$SpeculosKey = "AAAAC3NzaC1lZDI1NTE5AAAAIAqcocsmbdi1GiH4KgTy+TFtIgQxfaABSCkblCmKfoYR"
$Dir = Join-Path $HOME "nano-ssh-agent"
$HostDir = Join-Path $Dir "host"
$PubFile = Join-Path $HOME ".ssh\ledger_real.pub"
$Remote = $Target

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
# Keep the window open when started with right-click > Run with PowerShell
function Wait-Close { Read-Host "`nPress Enter to close" | Out-Null }
function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; Wait-Close; exit 1 }
trap { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red; Wait-Close; exit 1 }
function Pause-For($msg) { Read-Host "$msg, then press Enter" | Out-Null }
function Check-Exit($what) { if ($LASTEXITCODE -ne 0) { Fail "$what failed (exit $LASTEXITCODE)" } }
function Pipe-Exists { return ([System.IO.Directory]::GetFiles("\\.\pipe\") -contains $Pipe) }

# ---------------------------------------------------------------- prerequisites
Step "Checking prerequisites"
$missing = @()
foreach ($cmd in @("ssh", "scp", "ssh-add", "node", "npm")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { $missing += $cmd }
}
$PyExe = $null
$PyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) { $PyExe = "py"; $PyArgs = @("-3") }
elseif (Get-Command python -ErrorAction SilentlyContinue) { $PyExe = "python" }
elseif (-not $SkipLoad) { $missing += "python" }
if ($missing.Count -gt 0) {
    Write-Host "Missing: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "Install with:  winget install Python.Python.3.12 OpenJS.NodeJS.LTS"
    Write-Host "OpenSSH client: Settings > System > Optional features > OpenSSH Client"
    Write-Host "Then open a NEW PowerShell window and run this script again."
    Read-Host "`nPress Enter to close" | Out-Null
    exit 1
}

if ($Key -eq "") {
    foreach ($name in @("id_ed25519", "id_ecdsa", "id_rsa")) {
        $candidate = Join-Path $HOME ".ssh\$name"
        if (Test-Path $candidate) { $Key = $candidate; break }
    }
}
$KeyArgs = @()
if ($Key -ne "") {
    if (-not (Test-Path $Key)) { Fail "key file not found: $Key" }
    $KeyArgs = @("-i", $Key, "-o", "IdentitiesOnly=yes")
    Write-Host "Using existing key $Key for the build host"
} else {
    Write-Host "No key file given or found; relying on ~/.ssh/config or your usual agent"
}

# ---------------------------------------------------------------- fetch files
Step "Fetching files from $Remote (port $Port)"
New-Item -ItemType Directory -Force -Path $HostDir | Out-Null
# Use the usual Windows agent (if any) for these connections, not the Ledger one
Remove-Item Env:SSH_AUTH_SOCK -ErrorAction SilentlyContinue
# One scp (one passphrase prompt) into $Dir, then move the host files.
# Never end a path argument with "\": PowerShell 5.1 quotes paths containing spaces
# and a trailing backslash would escape the closing quote.
& scp -P $Port @KeyArgs "${Remote}:$RemoteDir/build/nanos2/bin/app.*" "${Remote}:$RemoteDir/host/*.js" "${Remote}:$RemoteDir/host/package*.json" $Dir
Check-Exit "scp of the files"
Move-Item -Force -Path (Join-Path $Dir "*.js"), (Join-Path $Dir "package*.json") -Destination $HostDir

# ---------------------------------------------------------------- load the app
if (-not $SkipLoad) {
    Step "Installing the Nano SSH Agent app on the device"
    Write-Host "Quit Ledger Live completely (also from the system tray)."
    Pause-For "Plug in the Nano S Plus, unlock it and stay on the dashboard"
    $venv = Join-Path $Dir "ledger-venv"
    if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
        & $PyExe @PyArgs -m venv $venv
        Check-Exit "python venv creation"
    }
    $vpy = Join-Path $venv "Scripts\python.exe"
    & $vpy -m pip install --quiet --upgrade ledgerblue
    Check-Exit "pip install ledgerblue"
    Write-Host "On the device: allow the unsafe manager, confirm the install, enter your PIN."
    & $vpy -m ledgerblue.runScript --scp --fileName "$Dir\app.apdu" --elfFile "$Dir\app.elf"
    Check-Exit "loading the app (see the error above)"
}

# ---------------------------------------------------------------- agent
Step "Installing agent dependencies"
Push-Location $HostDir
& npm install --no-fund --no-audit
$npmExit = $LASTEXITCODE
Pop-Location
if ($npmExit -ne 0) { Fail "npm install failed (exit $npmExit)" }

Step "Starting the agent"
Pause-For "Open the 'Nano SSH Agent' app on the device"
if (Pipe-Exists) {
    Write-Host "An agent is already listening on $Pipe, reusing it."
} else {
    $cmd = "Set-Location '$HostDir'; `$env:LEDGER_TRANSPORT='usb'; node agent.js"
    Start-Process powershell -ArgumentList @("-NoExit", "-Command", $cmd) | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Pipe-Exists) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    if (-not (Pipe-Exists)) { Fail "the agent did not start: look at the agent window for the error" }
    Write-Host "Agent running in a separate window (keep it open)."
}

# ---------------------------------------------------------------- public key
Step "Reading the public key from the device"
$env:SSH_AUTH_SOCK = $Pipe
$pubLine = (& ssh-add -L | Select-Object -First 1)
Check-Exit "ssh-add -L (is the Nano SSH Agent app open and the device unlocked?)"
Remove-Item Env:SSH_AUTH_SOCK
if ($pubLine -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+ ledger$') { Fail "unexpected key: $pubLine" }
if ($pubLine -like "*$SpeculosKey*") { Fail "this is the Speculos test key, not your device" }
New-Item -ItemType Directory -Force -Path (Split-Path $PubFile) | Out-Null
Set-Content -Path $PubFile -Value $pubLine -Encoding ascii
Write-Host "Saved $PubFile"
Write-Host $pubLine

# ---------------------------------------------------------------- authorize on build host
Step "Adding the key to $Remote ~/.ssh/authorized_keys (using your existing key)"
# Sent over stdin to bash, so no PowerShell quoting issues. Existing keys are kept;
# a missing trailing newline is fixed first so the new key never joins another line.
$script = @"
set -e
k='$pubLine'
f="`$HOME/.ssh/authorized_keys"
mkdir -p "`$HOME/.ssh" && chmod 700 "`$HOME/.ssh"
touch "`$f" && chmod 600 "`$f"
if grep -qxF "`$k" "`$f"; then
  echo 'Ledger key already authorized'
else
  if [ -s "`$f" ] && [ -n "`$(tail -c1 "`$f")" ]; then echo >> "`$f"; fi
  echo "`$k" >> "`$f"
  echo 'Ledger key added'
fi
"@
$script = $script -replace "`r", ""
$script | & ssh -p $Port @KeyArgs $Remote "tr -d '\r' | bash -s"
Check-Exit "adding the key on the build host"

# ---------------------------------------------------------------- test
Step "Test login with the Ledger only"
Write-Host "Approve 'Sign SSH login?' on the device."
$env:SSH_AUTH_SOCK = $Pipe
& ssh -p $Port -o IdentitiesOnly=yes -i $PubFile $Remote "echo LOGIN-OK: logged in with the Ledger key"
$loginExit = $LASTEXITCODE
if ($loginExit -ne 0) { Fail "login with the Ledger failed (exit $loginExit): check the agent window" }

Write-Host "`nDone." -ForegroundColor Green
Write-Host "Next time: start the agent:"
Write-Host "  cd `"$HostDir`"; `$env:LEDGER_TRANSPORT='usb'; node agent.js"
Write-Host "then in any window:"
Write-Host "  `$env:SSH_AUTH_SOCK = '$Pipe'"
Write-Host "  ssh -p $Port -o IdentitiesOnly=yes -i `"$PubFile`" $Remote"
Write-Host "Your old key is still authorized on the build host: keep it as a backup way in."
Wait-Close

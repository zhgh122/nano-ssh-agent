# One-time setup so VS Code (Remote-SSH) logs into a server with the Ledger, no command line.
#
# How to run: right-click this file > "Run with PowerShell". Answer the pop-ups.
# Requires: setup-windows.ps1 already run once (app on the device, agent files, key saved).
#
# What it does (each step can be run again safely):
#   1. starts the agent now, hidden, and at every Windows login (Startup shortcut),
#      plus a "Start Nano SSH Agent" entry in the Start menu
#   2. sets SSH_AUTH_SOCK for your user so VS Code's ssh uses the agent
#   3. adds a host to ~/.ssh/config that logs in with the Ledger key only (backup kept)
#   4. adds Remote-SSH settings to VS Code (longer timeout, no agent forwarding; backup kept)
#   5. installs the Remote-SSH extension if VS Code's "code" command is available
#
# ASCII only on purpose: Windows PowerShell 5.1 misreads UTF-8 files without BOM.

$ErrorActionPreference = "Stop"
$Pipe = "\\.\pipe\nano-ssh-agent"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# ------------------------------------------------------------------ helpers (testable)

# Append a Host block to an ssh config unless that alias already exists.
# Returns "added" or "exists".
function Add-SshHost([string]$ConfigPath, [string]$Alias, [string]$HostName, [int]$Port,
                     [string]$User, [string]$IdentityFile) {
    $text = ""
    if (Test-Path $ConfigPath) { $text = [System.IO.File]::ReadAllText($ConfigPath) }
    $pattern = "(?im)^\s*Host\s+(.*\s)?" + [regex]::Escape($Alias) + "(\s|$)"
    if ($text -match $pattern) { return "exists" }
    $block = "Host $Alias`n    HostName $HostName`n    Port $Port`n    User $User`n" +
             "    IdentityFile $IdentityFile`n    IdentitiesOnly yes`n"
    if ($text.Length -gt 0 -and -not $text.EndsWith("`n")) { $text += "`n" }
    if ($text.Length -gt 0) { $text += "`n" }
    $text += "# Added by nano-ssh-agent: login with the Ledger`n" + $block
    # OpenSSH for Windows does not accept a BOM in its config
    [System.IO.File]::WriteAllText($ConfigPath, $text, $Utf8NoBom)
    return "added"
}

# Insert settings into a VS Code settings.json (JSON with comments) without reformatting it.
# $Settings: ordered map of key -> JSON value text. Keys already present are left alone.
# Returns the list of keys that were added.
function Add-VsCodeSettings([string]$SettingsPath, $Settings) {
    $text = ""
    if (Test-Path $SettingsPath) { $text = [System.IO.File]::ReadAllText($SettingsPath) }
    if ($text.Trim() -eq "") { $text = "{`n}" }
    $added = @()
    $lines = @()
    foreach ($key in $Settings.Keys) {
        if ($text -notmatch ('"' + [regex]::Escape($key) + '"\s*:')) {
            $lines += "    `"$key`": $($Settings[$key])"
            $added += $key
        }
    }
    if ($added.Count -eq 0) { return $added }
    $brace = $text.IndexOf("{")
    if ($brace -lt 0) { throw "settings.json has no opening brace: $SettingsPath" }
    $rest = $text.Substring($brace + 1)
    $isEmpty = ($rest.Trim() -eq "}")
    $insert = "`n" + ($lines -join ",`n")
    if (-not $isEmpty) { $insert += "," }
    $text = $text.Substring(0, $brace + 1) + $insert + $rest
    [System.IO.File]::WriteAllText($SettingsPath, $text, $Utf8NoBom)
    return $added
}

function Backup-File([string]$Path) {
    if (Test-Path $Path) {
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        Copy-Item $Path "$Path.bak-$stamp"
    }
}

# Stop here when dot-sourced (tests load the helpers only)
if ($MyInvocation.InvocationName -eq ".") { return }

# ------------------------------------------------------------------ UI helpers
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
$Title = "nano-ssh-agent setup"
function Info($msg) { [void][System.Windows.Forms.MessageBox]::Show($msg, $Title, "OK", "Information") }
function Fail($msg) { [void][System.Windows.Forms.MessageBox]::Show($msg, $Title, "OK", "Error"); exit 1 }
function Ask($prompt, $default) { return [Microsoft.VisualBasic.Interaction]::InputBox($prompt, $Title, $default) }

try {
    # -------------------------------------------------------------- checks
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Fail "Node.js is not installed. Install the LTS version from https://nodejs.org, then run this again."
    }
    $HostDir = Join-Path $HOME "nano-ssh-agent\host"
    $AgentJs = Join-Path $HostDir "agent.js"
    $SockJs = Join-Path $HostDir "lib\sock-path.js"
    if (-not (Test-Path $AgentJs) -or -not (Test-Path $SockJs) -or
        -not (Select-String -Path $SockJs -Pattern "nano-ssh-agent" -Quiet)) {
        Fail "The agent is not installed in $HostDir.`n`nRun setup-windows.ps1 first (it installs the app on the device and the agent)."
    }
    $PubFile = Join-Path $HOME ".ssh\ledger_real.pub"
    if (-not (Test-Path $PubFile)) {
        Fail "Your Ledger public key ($PubFile) was not found.`n`nRun setup-windows.ps1 first."
    }

    # -------------------------------------------------------------- questions
    $target = Ask "Server to log into, as user@address`n(example: ubuntu@203.0.113.10)" ""
    if ($target -notmatch '^[^@\s]+@[^@\s]+$') { Fail "Expected user@address, got: '$target'" }
    $user, $address = $target.Split("@", 2)
    $portText = Ask "SSH port of the server (22 unless you changed it)" "22"
    $port = 0
    if (-not [int]::TryParse($portText, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { Fail "Invalid port: '$portText'" }
    $alias = Ask "Name for this server in VS Code (letters, digits, - and _ only)" "server-ledger"
    if ($alias -notmatch '^[A-Za-z0-9_-]+$') { Fail "Invalid name: '$alias'" }

    # -------------------------------------------------------------- 1. agent at login + now
    $AppDir = Join-Path $env:LOCALAPPDATA "nano-ssh-agent"
    New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
    $Launcher = Join-Path $AppDir "start-agent.ps1"
    $LogFile = Join-Path $AppDir "agent.log"
    $launcherText = @"
# Starts the nano-ssh-agent in the background (created by setup-vscode-windows.ps1)
if ([System.IO.Directory]::GetFiles("\\.\pipe\") -contains "$Pipe") { exit }
`$env:LEDGER_TRANSPORT = "usb"
Set-Location "$HostDir"
node agent.js *>> "$LogFile"
"@
    [System.IO.File]::WriteAllText($Launcher, $launcherText, $Utf8NoBom)

    $shell = New-Object -ComObject WScript.Shell
    $lnkArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Launcher`""
    $places = @(
        (Join-Path ([Environment]::GetFolderPath("Startup")) "nano-ssh-agent.lnk"),
        (Join-Path ([Environment]::GetFolderPath("Programs")) "Start Nano SSH Agent.lnk")
    )
    foreach ($lnkPath in $places) {
        $lnk = $shell.CreateShortcut($lnkPath)
        $lnk.TargetPath = (Join-Path $PSHOME "powershell.exe")
        $lnk.Arguments = $lnkArgs
        $lnk.WorkingDirectory = $HostDir
        $lnk.WindowStyle = 7
        $lnk.Description = "Ledger SSH agent for nano-ssh-agent"
        $lnk.Save()
    }
    Start-Process -FilePath (Join-Path $PSHOME "powershell.exe") -WindowStyle Hidden -ArgumentList $lnkArgs
    $deadline = (Get-Date).AddSeconds(15)
    while (-not ([System.IO.Directory]::GetFiles("\\.\pipe\") -contains $Pipe) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
    }
    if (-not ([System.IO.Directory]::GetFiles("\\.\pipe\") -contains $Pipe)) {
        Fail "The agent did not start. Details are in:`n$LogFile"
    }

    # -------------------------------------------------------------- 2. SSH_AUTH_SOCK
    [Environment]::SetEnvironmentVariable("SSH_AUTH_SOCK", $Pipe, "User")

    # -------------------------------------------------------------- 3. ssh config
    $SshDir = Join-Path $HOME ".ssh"
    $SshConfig = Join-Path $SshDir "config"
    Backup-File $SshConfig
    $hostResult = Add-SshHost $SshConfig $alias $address $port $user "~/.ssh/ledger_real.pub"

    # -------------------------------------------------------------- 4. VS Code settings
    $settingsPath = Join-Path $env:APPDATA "Code\User\settings.json"
    New-Item -ItemType Directory -Force -Path (Split-Path $settingsPath) | Out-Null
    Backup-File $settingsPath
    $settings = [ordered]@{
        "remote.SSH.connectTimeout"         = "60"
        "remote.SSH.enableAgentForwarding"  = "false"
        "remote.SSH.showLoginTerminal"      = "true"
        "remote.SSH.remotePlatform"         = "{ `"$alias`": `"linux`" }"
    }
    $addedSettings = Add-VsCodeSettings $settingsPath $settings

    # -------------------------------------------------------------- 5. Remote-SSH extension
    $code = Get-Command code -ErrorAction SilentlyContinue
    if (-not $code) {
        $guess = Join-Path $env:LOCALAPPDATA "Programs\Microsoft VS Code\bin\code.cmd"
        if (Test-Path $guess) { $code = $guess }
    }
    $extMsg = "Install the 'Remote - SSH' extension in VS Code (Extensions panel)."
    if ($code) {
        & $code --install-extension ms-vscode-remote.remote-ssh --force *> $null
        if ($LASTEXITCODE -eq 0) { $extMsg = "Remote - SSH extension installed." }
    }

    # -------------------------------------------------------------- done
    $notes = @()
    if ($hostResult -eq "exists") { $notes += "A host named '$alias' already existed in ~/.ssh/config; it was left unchanged." }
    $skipped = @($settings.Keys | Where-Object { $addedSettings -notcontains $_ })
    if ($skipped.Count -gt 0) { $notes += "Already in your VS Code settings (left unchanged): $($skipped -join ', ')" }
    $notesText = ""
    if ($notes.Count -gt 0) { $notesText = "`n`nNote:`n" + ($notes -join "`n") }

    Info @"
Setup finished. $extMsg

The agent now runs in the background and starts by itself when you log in to Windows.

To connect:
1. Quit VS Code completely and open it again (only this first time).
2. Plug in the Ledger, unlock it, open the "Nano SSH Agent" app.
3. In VS Code click the Remote Explorer icon on the left, find "$alias" under SSH, click the arrow to connect.
4. Press Approve on the Ledger when it shows "Sign SSH login?".
5. File > Open Folder to open your project.

Only approve right after you clicked connect. Reject any prompt you did not expect.
If something fails, the agent log is: $LogFile$notesText
"@
} catch {
    Fail "Setup failed: $($_.Exception.Message)"
}

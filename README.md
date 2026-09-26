# nano-ssh-agent

A Ledger device application plus a small Node.js `ssh-agent` that keeps an SSH ed25519 key
on the device. Every SSH login must be approved on the device screen.

Based on the [Ledger C boilerplate](https://github.com/LedgerHQ/app-boilerplate) (Apache 2.0).

> [!CAUTION]
> **Independent, experimental project. Not affiliated with, endorsed by or supported by Ledger SAS.**
> "Ledger" and "Nano" are trademarks of Ledger SAS and are used here only to name the hardware
> this runs on. The code has not been audited. The device app is not signed by Ledger and must be
> sideloaded. Use at your own risk and keep another way into your servers.

> [!WARNING]
> Speculos uses a publicly known test seed. Any key derived under Speculos is public:
> never put it in an `authorized_keys` file that stays around.

## Layout

| Path | What it is |
| --- | --- |
| `src/` | Device app (C). `handler/sign_ssh.c` is the signing flow. |
| `host/ledger.js` | APDU helpers: `getPublicKey`, `sign` over Speculos or USB (`LEDGER_TRANSPORT`) |
| `host/agent.js` | `ssh-agent` protocol server on a Unix socket |
| `host/pubkey.js` | Turns a raw public key (hex) into an `ssh-ed25519` line |
| `host/verify.js` | Verifies a raw ed25519 signature |
| `host/test-apdu.js` | APDU-level tests against Speculos |
| `host/test-ssh-login.sh` | End-to-end login test against a throwaway local `sshd` |
| `host/run-speculos.sh` | Runs Speculos with its ports on `127.0.0.1` only |
| `host/setup-windows.ps1` | One-shot Windows setup (fetch, load, agent, authorize, test) |
| `host/setup-vscode-windows.ps1` | Windows: agent at login + VS Code Remote-SSH, via pop-ups |
| `host/speculos-test-key.pub` | Public key of the Speculos test seed, used by the tests only |
| `tests/standalone/` | Ragger functional tests (all devices) |
| `APP_SPECIFICATION.md` | APDU protocol |

## Build

Inside the `ledger-app-dev-tools` container, with the project mounted on `/app`:

```shell
make BOLOS_SDK=$NANOSP_SDK      # or $NANOX_SDK, $STAX_SDK, $FLEX_SDK, $APEX_P_SDK
```

## Derivation path

The key lives at `m/44'/1280529224'/0'/0'/0'` (1280529224 = `0x4C535348` = ASCII "LSSH"),
hardened at every level (SLIP-10 ed25519 only supports hardened derivation).

- `PATH_APP_LOAD_PARAMS = "44'/1280529224'"` in the `Makefile`: on a real device the OS refuses
  any derivation outside this prefix, so the app cannot reach keys of Bitcoin, Ethereum or any
  other wallet app on the same seed.
- The app checks the same prefix itself (`src/helper/ssh_path.c`), so Speculos (which does not
  enforce `PATH_APP_LOAD_PARAMS`) behaves the same. Other paths get `6A80`.
- The coin type is deliberately not `535348'` ("SSH"), which Ledger's SSH/PGP agent app uses:
  the two apps never share a key.
- The host uses `SSH_PATH` in `host/ledger.js`.

## Run on Speculos

```shell
host/run-speculos.sh                        # nanosp; Ctrl+C to stop
MODEL=stax ELF=build/stax/bin/app.elf host/run-speculos.sh
```

Speculos always binds its servers to `0.0.0.0`, and that can't be changed. The script
therefore runs it in its own container on the Docker bridge network and publishes the REST API
(5000) and APDU (9999) ports on `127.0.0.1` only. Do not run Speculos with `--network host`
or directly on a machine reachable from other hosts: anyone reaching those ports could press
buttons and get signatures.

`host/ledger.js` uses `SPECULOS_URL` (default `http://localhost:5000`). Buttons can be pressed
with e.g. `curl -XPOST -d '{"action":"press-and-release"}' localhost:5000/button/both`.

## Use the agent

```shell
cd host
npm install                                 # only needed for USB (hw-transport-node-hid)
node agent.js                               # Speculos; listens on /tmp/nano-ssh-agent.sock
export SSH_AUTH_SOCK=/tmp/nano-ssh-agent.sock
ssh-add -L                                  # prints the ssh-ed25519 public key
ssh user@server                             # approve "Sign SSH login?" on the device
```

The agent answers `SSH_AGENTC_REQUEST_IDENTITIES` (11) and `SSH_AGENTC_SIGN_REQUEST` (13);
every other request gets `SSH_AGENT_FAILURE` (5).

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `LEDGER_TRANSPORT` | `speculos` | `speculos` (REST API) or `usb` (real device over HID) |
| `SPECULOS_URL` | `http://localhost:5000` | Speculos REST API |
| `LEDGER_USB_TIMEOUT_MS` | `5000` | How long to look for a USB device before answering failure |
| `LEDGER_AGENT_SOCK` | `/tmp/nano-ssh-agent.sock` | Agent socket path (created with mode 0600) |

## Tests

```shell
# Ragger functional tests (in the container, after building for the device)
pip install -r tests/standalone/requirements.txt
pytest tests/standalone/ --tb=short -v --device nanosp

# Host-side tests against Speculos (nanosp) started with host/run-speculos.sh
node host/test-apdu.js
SSH_AUTH_SOCK=/tmp/nano-ssh-agent.sock host/test-ssh-login.sh   # agent must be running
```

`test-ssh-login.sh` starts `sshd` as the current user on `127.0.0.1` with a temporary
`authorized_keys`, and always stops it and deletes its files on exit. It never touches
`~/.ssh/authorized_keys`.

## Install on a real Nano S Plus

> [!IMPORTANT]
> - `host/speculos-test-key.pub` is the **Speculos** key (public test seed). Never authorize it on a real server.
>   Your real key comes from your device seed and is different.
> - The app is not signed by Ledger, so it is sideloaded. The device will warn that the app is
>   not genuine; this is expected for your own build.
> - Plug the device into **your own computer** and run the agent there. To use the key on hosts
>   you are logged into, use agent forwarding (`ssh -A`): every signature still needs a button
>   press on the device.

### 1. Prepare the device

1. In Ledger Live, update the Nano S Plus to the latest OS. The app is built with SDK API level 26;
   if the device OS does not match, loading fails with an API level error. In that case, update
   the device or build with the SDK matching its OS.
2. Quit Ledger Live: it keeps the USB device busy.
3. Plug the device in, unlock it and stay on the dashboard (no app open).

### 2. USB permissions (Linux host)

```shell
sudo tee /etc/udev/rules.d/20-ledger.rules <<'RULES'
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
KERNEL=="hidraw*", ATTRS{idVendor}=="2c97", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
RULES
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Unplug and replug the device afterwards. macOS needs no rules.

### 3. Build a release binary

Build without `DEBUG=1`, in the `ledger-app-dev-tools` container:

```shell
make clean
make BOLOS_SDK=$NANOSP_SDK
```

### 4. Load the app

With the container started with USB access
(`docker run --rm -it --privileged -v /dev/bus/usb:/dev/bus/usb -v "$(pwd):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest`):

```shell
make load BOLOS_SDK=$NANOSP_SDK
```

Or from the host with [ledgerblue](https://github.com/LedgerHQ/blue-loader-python) in a Python virtualenv:

```shell
python3 -m venv ~/ledger-venv && . ~/ledger-venv/bin/activate
pip install ledgerblue
python3 -m ledgerblue.runScript --scp --fileName build/nanos2/bin/app.apdu --elfFile build/nanos2/bin/app.elf
```

On the device: accept "Allow unsafe manager", review the install request for **Nano SSH Agent**, then
enter your PIN. The app then appears on the dashboard.

To remove it later: `make delete BOLOS_SDK=$NANOSP_SDK` (in the container).
Sideloaded apps must be loaded again after a device OS update.

### 5. Use it

Open **Nano SSH Agent** on the device ("Nano SSH Agent / app is ready"), then on the computer:

```shell
cd host
npm install
LEDGER_TRANSPORT=usb node agent.js
# in another terminal
export SSH_AUTH_SOCK=/tmp/nano-ssh-agent.sock
ssh-add -L > ~/.ssh/ledger_real.pub         # your real public key
ssh-copy-id -f -i ~/.ssh/ledger_real.pub user@server   # or append it to authorized_keys manually
ssh user@server                             # approve "Sign SSH login?" on the device
```

Quick check without SSH: `LEDGER_TRANSPORT=usb node ledger.js` prints the public key, then asks
the device to sign a test message.

### Windows

Quickest: `host/setup-windows.ps1` does all the steps below (fetch, load, npm install, start the
agent, authorize the key on the build host without touching existing keys, test the login):

```powershell
scp user@buildhost:nano-ssh-agent/host/setup-windows.ps1 $HOME\
powershell -ExecutionPolicy Bypass -File $HOME\setup-windows.ps1 -Target user@buildhost
# options: -Port 2222  -Key $HOME\.ssh\id_rsa  -RemoteDir path/to/repo  -SkipLoad
```

Manual steps:

The build still happens in the Linux container; only the loading, the agent and `ssh` run on
Windows. No udev rules are needed. Requirements: [Python 3](https://www.python.org/downloads/),
[Node.js LTS](https://nodejs.org/) and the OpenSSH client built into Windows 10/11.

In PowerShell **on the Windows PC** (replace `user@buildhost` with the machine holding the build; if its
SSH server is not on port 22, add `-P <port>` to `scp` and `-p <port>` to `ssh`):

```powershell
mkdir nano-ssh-agent; cd nano-ssh-agent
scp "user@buildhost:nano-ssh-agent/build/nanos2/bin/app.*" .
mkdir host
scp "user@buildhost:nano-ssh-agent/host/*.js" "user@buildhost:nano-ssh-agent/host/package*.json" host/

# load the app (device unlocked, on the dashboard, Ledger Live closed)
py -m venv ledger-venv
Set-ExecutionPolicy -Scope Process Bypass   # allow the venv activation script
.\ledger-venv\Scripts\Activate.ps1
pip install ledgerblue
python -m ledgerblue.runScript --scp --fileName app.apdu --elfFile app.elf

# agent (open the Nano SSH Agent app on the device first)
cd host
npm install
$env:LEDGER_TRANSPORT = "usb"
node agent.js                               # listens on \\.\pipe\nano-ssh-agent
```

In a second PowerShell window:

```powershell
$env:SSH_AUTH_SOCK = "\\.\pipe\nano-ssh-agent"
ssh-add -L | Out-File -Encoding ascii $HOME\.ssh\ledger_real.pub
Get-Content $HOME\.ssh\ledger_real.pub | ssh user@buildhost "cat >> ~/.ssh/authorized_keys"
ssh -o IdentitiesOnly=yes -i $HOME\.ssh\ledger_real.pub user@buildhost
```

On Windows the agent uses the named pipe `\\.\pipe\nano-ssh-agent` instead of a Unix socket.
It does not conflict with the Windows "OpenSSH Authentication Agent" service, which uses
`\\.\pipe\openssh-ssh-agent`; `SSH_AUTH_SOCK` selects which agent `ssh` talks to.

### VS Code on Windows (no command line)

After `setup-windows.ps1` has run once, download `host/setup-vscode-windows.ps1`, right-click it
and choose **Run with PowerShell**, then answer the pop-ups (server `user@address`, port, a name).
It starts the agent in the background (and at every login), points `SSH_AUTH_SOCK` at it, adds the
server to `~/.ssh/config` with the Ledger key only, and sets Remote-SSH to a 60 s connect timeout
without agent forwarding. Existing files are backed up and existing settings are kept.

Then in VS Code: Remote Explorer → the server → connect → approve on the device.

### Troubleshooting

| Agent log / error | Cause |
| --- | --- |
| `No Ledger device found (timeout)` | Not plugged in, Ledger Live still open, or missing udev rules |
| `Ledger error: 5515 (device is locked...)` | Unlock the device |
| `6511`, `6e01`, `6d02` (`app is not open`) | Open the Nano SSH Agent app on the device |
| `6985 (rejected on device)` | Rejected on the device |
| `6901 (device is busy...)` | Another program is talking to the device |

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

## License

Apache License 2.0, see [LICENSE.md](LICENSE.md). This is a modified version of LedgerHQ's
app-boilerplate; see [NOTICE](NOTICE).


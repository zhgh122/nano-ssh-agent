# Ledger SSH

A Ledger device application plus a small Node.js `ssh-agent` that keeps an SSH ed25519 key
on the device. Every SSH login must be approved on the device screen.

Based on the [Ledger C boilerplate](https://github.com/LedgerHQ/app-boilerplate) (Apache 2.0).

> [!WARNING]
> Speculos uses a publicly known test seed. Any key derived under Speculos is public:
> never put it in an `authorized_keys` file that stays around.

## Layout

| Path | What it is |
| --- | --- |
| `src/` | Device app (C). `handler/sign_ssh.c` is the signing flow. |
| `host/ledger.js` | APDU helpers: `getPublicKey`, `sign` (Speculos transport) |
| `host/agent.js` | `ssh-agent` protocol server on a Unix socket |
| `host/pubkey.js` | Turns a raw public key (hex) into an `ssh-ed25519` line |
| `host/verify.js` | Verifies a raw ed25519 signature |
| `host/test-apdu.js` | APDU-level tests against Speculos |
| `host/test-ssh-login.sh` | End-to-end login test against a throwaway local `sshd` |
| `tests/standalone/` | Ragger functional tests (all devices) |
| `APP_SPECIFICATION.md` | APDU protocol |

## Build

Inside the `ledger-app-dev-tools` container, with the project mounted on `/app`:

```shell
make BOLOS_SDK=$NANOSP_SDK      # or $NANOX_SDK, $STAX_SDK, $FLEX_SDK, $APEX_P_SDK
```

## Run on Speculos

```shell
speculos build/nanos2/bin/app.elf --model nanosp --display headless
```

Speculos serves its REST API on port 5000 (`host/ledger.js` uses `SPECULOS_URL`,
default `http://localhost:5000`). Buttons can be pressed with e.g.
`curl -XPOST -d '{"action":"press-and-release"}' localhost:5000/button/both`.

## Use the agent

```shell
cd host
node agent.js                               # listens on /tmp/ledger-agent.sock
export SSH_AUTH_SOCK=/tmp/ledger-agent.sock
ssh-add -L                                  # prints the ssh-ed25519 public key
ssh user@server                             # approve "Sign SSH login?" on the device
```

The agent answers `SSH_AGENTC_REQUEST_IDENTITIES` (11) and `SSH_AGENTC_SIGN_REQUEST` (13);
every other request gets `SSH_AGENT_FAILURE` (5).

## Tests

```shell
# Ragger functional tests (in the container, after building for the device)
pip install -r tests/standalone/requirements.txt
pytest tests/standalone/ --tb=short -v --device nanosp

# Host-side tests against a running Speculos (nanosp)
node host/test-apdu.js
SSH_AUTH_SOCK=/tmp/ledger-agent.sock host/test-ssh-login.sh   # agent must be running
```

`test-ssh-login.sh` starts `sshd` as the current user on `127.0.0.1` with a temporary
`authorized_keys`, and always stops it and deletes its files on exit. It never touches
`~/.ssh/authorized_keys`.

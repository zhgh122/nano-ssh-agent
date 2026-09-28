# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Local dashboard (web UI + backend on 127.0.0.1, Electron wrapper): live agent/device/app/approval
  status, public key with fingerprint and copy, signing history, agent Start/Stop, commands to add
  the key to a server
- Signing history file (no signatures or signed data stored), with user and verified server
- `session-bind@openssh.com` support: the host key signature is verified before a server is named

### Changed

- The agent is split into `host/lib/` modules; `agent.js` is a thin command line over them
- An agent no longer deletes the socket of another running agent; it refuses to start instead
- USB transport uses `@ledgerhq/hw-transport-node-hid-noevents` (no `usb` native module, which
  crashed Electron on exit)

## [0.1.0] - 2026-09-26

### Added

- SIGN_SSH (INS 0x10): ed25519 signature of an SSH authentication message after on-device approval
- Host `ssh-agent` (Node.js) using the device for REQUEST_IDENTITIES and SIGN_REQUEST

### Changed

- Renamed from Boilerplate to Nano SSH Agent
- GET_PUBLIC_KEY returns a 32-byte SLIP-10 ed25519 key; the on-screen confirmation mode was removed
- Only the ed25519 curve is requested
- Keys are derived under the app-specific path `m/44'/1280529224'` (all levels hardened) instead of
  `44'/1'`; `PATH_APP_LOAD_PARAMS` and the app both refuse any other path
- Speculos is started with `host/run-speculos.sh`, which only exposes its ports on 127.0.0.1
- SIGN_SSH is a state machine: chunks must be sequential, and every command is refused while
  the approval screen is displayed (defense in depth on top of the SDK reply-pending latch)

### Removed

- Boilerplate transaction/token signing (SIGN_TX, SIGN_TOKEN_TX), PROVIDE_TOKEN_INFO, swap support,
  dummy settings and their tests

The entries below are from the upstream boilerplate.

## [2.1.0] - 2023-10-06

### Changed

- Improving the settings use case in order to be able to use app settings parameters stored in NVM
- add a NBGL use case choice when a setting switch is toggled

## [2.0.0] - 2023-07-10

### Added

- Stax porting
- Extensive CI, including mandatory `guidelines_enforcer.yml`
- Extensive `README.md` to modify/compile/test the application on most OS (Linux, MacOS, Windows)
- Extensive `Ragger` tests

### Changed

- Simplified `Makefile` (complexity delegated to the SDK's `Makefile.standard_app`)
- Simplified overall code (moved into the SDK)
- Improving several UI flows to fit Ledger UI guidelines
- Removing `TRY`/`CATCH` usage (using `_no_throw` SDK functions)
- Cleaning unnecessary resources (moved into the SDK)

### Fixed

- Multiple minor lint, prototype or misspell fixes

## [1.0.1] - 2021-01-11

### Fix

- Missing header includes

## [1.0.0] - 2020-11-19

### Added

- Initial commit with the brand new Boilerplate application

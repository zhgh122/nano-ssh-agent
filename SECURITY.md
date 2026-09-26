# Security

This is an experimental, unaudited project. It is not a Ledger product.

## What it protects

- The SSH private key is derived on the device (SLIP-10 ed25519) and never leaves it.
- Every signature needs a button press on the device. Malware on the computer cannot log in
  silently, even with full control of the agent.
- The app can only derive keys under `m/44'/1280529224'`, both through `PATH_APP_LOAD_PARAMS`
  (enforced by the device OS) and through its own check, so it cannot reach the keys of wallet
  apps on the same seed.
- While the approval screen is displayed, every other command is refused, so the message being
  approved cannot be changed or replaced.

## What it does not protect (known limitations)

- **The approval screen does not show what is being signed.** It only shows "Sign SSH login?".
  If the computer is compromised, an attacker can start their own login (to any server that
  trusts this key) at the moment you expect a prompt, and your approval will authorize it.
  Only approve right after you started a connection yourself, and reject any unexpected prompt.
  Parsing the SSH authentication request and displaying the user name and key on the device is
  planned.
- The app signs any message of up to 510 bytes on the allowed path after approval; it does not
  yet check that the message is an SSH authentication request.
- With agent forwarding (`ssh -A`), anyone with root on the remote host can ask your agent for
  signatures; each one still needs a button press on the device.
- Speculos (the emulator) uses a public test seed. Keys derived there, including
  `host/speculos-test-key.pub`, are public and must never be authorized anywhere.
- The device app is not signed by Ledger. Only install builds you made yourself from source you
  reviewed.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
("Report a vulnerability" in the repository's Security tab).

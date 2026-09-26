# Technical Specification

## About

This documentation describes the APDU interface of the Nano SSH Agent application.

The application covers the following functionalities:

- Get an ed25519 public key (SLIP-10) given a BIP 32 path
- Sign an SSH authentication message with ed25519, after on-device approval
- Retrieve the app version
- Retrieve the app name

Keys are derived with SLIP-10 ed25519, which only supports hardened derivation.
The app only derives under `m/44'/1280529224'` (1280529224 = `0x4C535348` = "LSSH"), with every
level hardened and at least one level below the prefix. This is enforced by the OS on a real
device (`PATH_APP_LOAD_PARAMS` in the `Makefile`) and by the app itself: any other path is
refused with `6A80`. The host tools use `m/44'/1280529224'/0'/0'/0'`.

The application interface can be accessed over HID or BLE.

## APDUs

### GET PUBLIC KEY

#### Description

Returns the ed25519 public key for the given BIP 32 path. No user interaction is required.

#### Coding

##### `Command`

| CLA | INS | P1  | P2  | Lc       |
| --- | --- | --- | --- | ---      |
| E0  | 05  | 00  | 00  | variable |

##### `Input data`

| Description                                      | Length |
| ---                                              | ---    |
| Number of BIP 32 derivations to perform (max 10) | 1      |
| First derivation index (big endian)              | 4      |
| ...                                              | 4      |
| Last derivation index (big endian)               | 4      |

No trailing bytes are allowed.

##### `Output data`

| Description                                   | Length |
| ---                                           | ---    |
| ed25519 public key, RFC 8032 encoding         | 32     |

### SIGN SSH

#### Description

Signs a message with ed25519 (RFC 8032, the message is signed as-is) after the user
approves the "Sign SSH login?" screen. The message is typically the
`SSH_MSG_USERAUTH_REQUEST` data an SSH client asks an agent to sign.

The derivation path is sent first, then the message is sent in one or more chunks.
The message is limited to 510 bytes.

#### Coding

##### `Command`

| CLA | INS | P1                | P2                   | Lc       |
| --- | --- | ---               | ---                  | ---      |
| E0  | 10  | 00 : path chunk   | 80 : more chunks     | variable |
|     |     | 01..03 : message chunk index | 00 : last chunk |   |

- Chunk 0 (P1 = 00) must carry the path and P2 = 80.
- Message chunks must be numbered 01, 02, 03 in order. A gap or a repeated index aborts the
  flow with 6985.
- The last message chunk has P2 = 00; the device then shows the approval screen and
  answers only once the user has approved or rejected.
- While the approval screen is displayed, every other command is refused (the SDK answers
  6901, and the app itself answers 6985 if a command reaches it), so the message being
  approved cannot be changed or wiped.

##### `Input data (chunk 0)`

| Description                                      | Length |
| ---                                              | ---    |
| Number of BIP 32 derivations to perform (max 10) | 1      |
| First derivation index (big endian)              | 4      |
| ...                                              | 4      |
| Last derivation index (big endian)               | 4      |

##### `Input data (message chunks)`

| Description        | Length      |
| ---                | ---         |
| Part of message    | 1 to 255    |

##### `Output data`

Intermediate chunks return no data. The last chunk returns:

| Description             | Length |
| ---                     | ---    |
| ed25519 signature       | 64     |

The signing context is wiped after the user's answer and after any error.

### GET APP VERSION

#### Coding

| CLA | INS | P1  | P2  | Lc  |
| --- | --- | --- | --- | --- |
| E0  | 03  | 00  | 00  | 00  |

##### `Output data`

| Description                       | Length |
| ---                               | ---    |
| Application major version         | 1      |
| Application minor version         | 1      |
| Application patch version         | 1      |

### GET APP NAME

#### Coding

| CLA | INS | P1  | P2  | Lc  |
| --- | --- | --- | --- | --- |
| E0  | 04  | 00  | 00  | 00  |

##### `Output data`

| Description           | Length   |
| ---                   | ---      |
| Application name      | variable |

## Status Words

| SW       | SW name                      | Description                                               |
| ---      | ---                          | ---                                                       |
|   9000   | OK                           | Success                                                   |
|   6901   | SWO_COMMAND_NOT_ACCEPTED     | (SDK) command sent while the device still owes a reply    |
|   6985   | SWO_CONDITIONS_NOT_SATISFIED | Rejected by user, or command received in a wrong state    |
|   6A80   | SWO_INCORRECT_DATA           | Path outside `m/44'/1280529224'`, not fully hardened, or signing failed |
|   6A86   | SWO_INCORRECT_P1_P2          | Either P1 or P2 is incorrect                              |
|   6A87   | SWO_WRONG_DATA_LENGTH        | Malformed path, or message longer than 510 bytes          |
|   6D00   | SWO_INVALID_INS              | No command exists with INS                                |
|   6E00   | SWO_INVALID_CLA              | Bad CLA used for this application                         |

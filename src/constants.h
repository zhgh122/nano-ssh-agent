#pragma once

/**
 * Instruction class of the Nano SSH Agent application.
 */
#define CLA 0xE0

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Maximum length of an SSH message to sign (bytes).
 * An OpenSSH user authentication request is typically < 300 bytes.
 */
#define MAX_SSH_MESSAGE_LEN 510

/**
 * Length of an ed25519 public key (bytes).
 */
#define ED25519_PUBKEY_LEN 32

/**
 * Length of an ed25519 signature (bytes).
 */
#define ED25519_SIG_LEN 64

/**
 * Derivation path prefix reserved for this app: m/44'/1280529224'
 * (1280529224 = 0x4C535348 = ASCII "LSSH"). Must match PATH_APP_LOAD_PARAMS
 * in the Makefile. Every level below it must be hardened (SLIP-10 ed25519).
 */
#define SSH_PATH_PURPOSE    (0x80000000u | 44u)
#define SSH_PATH_COIN_TYPE  (0x80000000u | 0x4C535348u)
#define SSH_PATH_PREFIX_LEN 2

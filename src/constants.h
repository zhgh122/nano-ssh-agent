#pragma once

/**
 * Instruction class of the Ledger SSH application.
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

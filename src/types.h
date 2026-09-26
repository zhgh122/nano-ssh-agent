#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "bip32.h"

#include "constants.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,     /// version of the application
    GET_APP_NAME = 0x04,    /// name of the application
    GET_PUBLIC_KEY = 0x05,  /// ed25519 public key of corresponding BIP32 path
    SIGN_SSH = 0x10,        /// sign an SSH authentication message with BIP32 path
} command_e;

/**
 * Enumeration with the state of the SIGN_SSH flow.
 */
typedef enum {
    SSH_STATE_NONE = 0,          /// no signing flow in progress
    SSH_STATE_RECEIVING,         /// path received, message chunks expected
    SSH_STATE_WAITING_APPROVAL,  /// message complete, approval screen displayed
} ssh_state_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[65];  /// format (1), x-coordinate (32), y-coordinate (32)
    uint8_t chain_code[32];      /// for public key derivation
} pubkey_ctx_t;

/**
 * Structure for SSH signing context information.
 */
typedef struct {
    uint8_t message[MAX_SSH_MESSAGE_LEN];  /// raw message to sign, accumulated from APDUs
    size_t message_len;                    /// length of message
    uint8_t signature[ED25519_SIG_LEN];    /// ed25519 signature
    size_t signature_len;                  /// length of signature
    uint8_t next_chunk;                    /// P1 expected for the next message chunk
} ssh_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    ssh_state_e state;  /// state of the SIGN_SSH flow
    union {
        pubkey_ctx_t pk_info;  /// public key context
        ssh_ctx_t ssh_info;    /// SSH signing context
    };
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// length of BIP32 path
} global_ctx_t;

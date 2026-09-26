#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "buffer.h"

/**
 * Handler for SIGN_SSH command. If successfully parse BIP32 path and message,
 * sign the message with ed25519 after user approval and send the signature.
 *
 * Chunk 0 carries the BIP32 path, chunks 1..n carry the message to sign.
 *
 * @param[in,out] cdata
 *   Command data with BIP32 path (chunk 0) or part of the message (chunk > 0).
 * @param[in]     chunk
 *   Index number of the APDU chunk.
 * @param[in]     more
 *   Whether more APDU chunks are expected.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_sign_ssh(buffer_t *cdata, uint8_t chunk, bool more);

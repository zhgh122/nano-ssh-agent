/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "send_response.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"

int helper_send_response_pubkey(void) {
    // raw_public_key is 0x04 || X (32, big-endian) || Y (32, big-endian).
    // RFC 8032 encoding is Y in little-endian with the parity of X in the top bit.
    const uint8_t *raw = G_context.pk_info.raw_public_key;
    uint8_t out[ED25519_PUBKEY_LEN];

    for (size_t i = 0; i < ED25519_PUBKEY_LEN; i++) {
        out[i] = raw[1 + 2 * ED25519_PUBKEY_LEN - 1 - i];
    }
    if (raw[ED25519_PUBKEY_LEN] & 1) {
        out[ED25519_PUBKEY_LEN - 1] |= 0x80;
    }
    return io_send_response_pointer(out, sizeof(out), SWO_SUCCESS);
}

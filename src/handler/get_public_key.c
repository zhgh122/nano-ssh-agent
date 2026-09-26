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

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"
#include "crypto_helpers.h"

#include "get_public_key.h"
#include "globals.h"
#include "types.h"
#include "sw.h"
#include "send_response.h"
#include "ssh_path.h"

int handler_get_public_key(buffer_t *cdata) {
    explicit_bzero(&G_context, sizeof(G_context));

    if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(cdata, G_context.bip32_path, (size_t) G_context.bip32_path_len) ||
        cdata->offset != cdata->size) {
        explicit_bzero(&G_context, sizeof(G_context));
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }
    if (!ssh_path_is_allowed(G_context.bip32_path, G_context.bip32_path_len)) {
        explicit_bzero(&G_context, sizeof(G_context));
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    cx_err_t error = bip32_derive_with_seed_get_pubkey_256(HDW_ED25519_SLIP10,
                                                           CX_CURVE_Ed25519,
                                                           G_context.bip32_path,
                                                           G_context.bip32_path_len,
                                                           G_context.pk_info.raw_public_key,
                                                           G_context.pk_info.chain_code,
                                                           CX_SHA512,
                                                           NULL,
                                                           0);
    if (error != CX_OK) {
        explicit_bzero(&G_context, sizeof(G_context));
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    int ret = helper_send_response_pubkey();
    explicit_bzero(&G_context, sizeof(G_context));
    return ret;
}

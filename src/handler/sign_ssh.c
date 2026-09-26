#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // explicit_bzero

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"
#include "crypto_helpers.h"
#include "nbgl_use_case.h"

#include "sign_ssh.h"
#include "sw.h"
#include "globals.h"
#include "display.h"
#include "menu.h"

static cx_err_t sign_ssh_message(void) {
    size_t sig_len = sizeof(G_context.ssh_info.signature);

    cx_err_t err = bip32_derive_with_seed_eddsa_sign_hash_256(HDW_ED25519_SLIP10,
                                                              CX_CURVE_Ed25519,
                                                              G_context.bip32_path,
                                                              G_context.bip32_path_len,
                                                              CX_SHA512,
                                                              G_context.ssh_info.message,
                                                              G_context.ssh_info.message_len,
                                                              G_context.ssh_info.signature,
                                                              &sig_len,
                                                              NULL,
                                                              0);
    if (err == CX_OK && sig_len != ED25519_SIG_LEN) {
        return CX_INTERNAL_ERROR;
    }
    G_context.ssh_info.signature_len = sig_len;
    return err;
}

static void ssh_choice(bool confirm) {
    if (!confirm) {
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    } else if (sign_ssh_message() != CX_OK) {
        io_send_sw(SWO_INCORRECT_DATA);
    } else {
        io_send_response_pointer(G_context.ssh_info.signature,
                                 G_context.ssh_info.signature_len,
                                 SWO_SUCCESS);
    }
    explicit_bzero(&G_context, sizeof(G_context));
    ui_menu_main();
}

static uint16_t init_sign_context(buffer_t *cdata) {
    explicit_bzero(&G_context, sizeof(G_context));

    if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(cdata, G_context.bip32_path, (size_t) G_context.bip32_path_len) ||
        cdata->offset != cdata->size) {
        explicit_bzero(&G_context, sizeof(G_context));
        return SWO_WRONG_DATA_LENGTH;
    }
    return SWO_SUCCESS;
}

static uint16_t accumulate_message(buffer_t *cdata) {
    ssh_ctx_t *ctx = &G_context.ssh_info;

    if (G_context.bip32_path_len == 0) {
        return SWO_CONDITIONS_NOT_SATISFIED;
    }
    if (cdata->size > sizeof(ctx->message) - ctx->message_len) {
        return SWO_WRONG_DATA_LENGTH;
    }
    if (!buffer_move(cdata, ctx->message + ctx->message_len, cdata->size)) {
        return SWO_INCORRECT_DATA;
    }
    ctx->message_len += cdata->size;
    return SWO_SUCCESS;
}

int handler_sign_ssh(buffer_t *cdata, uint8_t chunk, bool more) {
    uint16_t sw;

    if (chunk == 0) {
        return io_send_sw(init_sign_context(cdata));
    }

    sw = accumulate_message(cdata);
    if (sw != SWO_SUCCESS) {
        explicit_bzero(&G_context, sizeof(G_context));
        return io_send_sw(sw);
    }
    if (more) {
        return io_send_sw(SWO_SUCCESS);
    }

    nbgl_useCaseChoice(&ICON_APP_SSH, "Sign SSH login?", APPNAME, "Approve", "Reject", ssh_choice);
    return 0;
}

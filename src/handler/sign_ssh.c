#include "crypto_helpers.h"
#include "globals.h"

cx_err_t sign_ssh_message(void) {
    size_t sig_len = 64;

    cx_err_t err = bip32_derive_with_seed_eddsa_sign_hash_256(
        HDW_ED25519_SLIP10,             // derivation_mode
        CX_CURVE_Ed25519,               // curve
        G_context.bip32_path,           // path
        G_context.bip32_path_len,       // path_len
        CX_SHA512,                      // hashID
        G_context.tx_info.raw_tx,       // ข้อความที่สะสมไว้
        G_context.tx_info.raw_tx_len,   // ความยาวข้อความ
        G_context.tx_info.signature,    // ที่เก็บลายเซ็น
        &sig_len,                       // ขาเข้า 64 / ขาออก ความยาวจริง
        NULL,                           // seed = ใช้ของเครื่อง
        0);                             // seed_len

    G_context.tx_info.signature_len = sig_len;
    return err;
}
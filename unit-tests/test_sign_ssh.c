/*
 * Unit tests for src/handler/sign_ssh.c and the approval guard of
 * src/apdu/dispatcher.c.
 *
 * The SDK IO layer already refuses APDUs while a reply is pending (6901), so
 * the app-level guard cannot be reached from Speculos: these tests call the
 * handler/dispatcher directly to prove the app itself fails closed.
 *
 * io is a CMock mock (io_send_sw is an inline wrapper over
 * io_send_response_buffers); buffer/bip32 parsing is the real SDK code;
 * NBGL, the menu and the SDK signing helper are hand-stubbed.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "unity.h"

#include "Mockio.h"
#include "Mockget_version.h"
#include "Mockget_app_name.h"
#include "Mockget_public_key.h"

#include "nbgl_use_case.h"
#include "crypto_helpers.h"
#include "glyphs.h"

#include "sign_ssh.h"
#include "dispatcher.h"
#include "globals.h"
#include "types.h"
#include "menu.h"
#include "sw.h"

global_ctx_t G_context;

#if defined(TARGET_STAX) || defined(TARGET_FLEX)
const nbgl_icon_details_t C_app_ssh_64px;
#elif defined(TARGET_APEX_P)
const nbgl_icon_details_t C_app_ssh_48px;
#else
const nbgl_icon_details_t C_app_ssh_14px;
#endif

// ---- captures ----
static uint16_t g_last_sw;
static size_t g_last_len;
static int g_sw_count;
static nbgl_choiceCallback_t g_choice_cb;
static int g_prompt_count;
static int g_sign_count;
static uint8_t g_signed_msg[MAX_SSH_MESSAGE_LEN];
static size_t g_signed_len;

static int io_send_cb(const buffer_t *rdatalist, size_t count, uint16_t sw, int cmock_num_calls) {
    (void) cmock_num_calls;
    g_last_sw = sw;
    g_last_len = (count > 0) ? rdatalist[0].size : 0;
    g_sw_count++;
    return 0;
}

// ---- hand stubs ----
void nbgl_useCaseChoice(const nbgl_icon_details_t *icon,
                        const char *message,
                        const char *subMessage,
                        const char *confirmText,
                        const char *rejectString,
                        nbgl_choiceCallback_t callback) {
    (void) icon;
    (void) message;
    (void) subMessage;
    (void) confirmText;
    (void) rejectString;
    g_choice_cb = callback;
    g_prompt_count++;
}

void ui_menu_main(void) {
}

// LEDGER_ASSERT(cmd != NULL) in the dispatcher; never triggered by these tests
void assert_exit(bool confirm) {
    (void) confirm;
    TEST_FAIL_MESSAGE("assert_exit called");
    abort();
}

cx_err_t bip32_derive_with_seed_eddsa_sign_hash_256(unsigned int derivation_mode,
                                                    cx_curve_t curve,
                                                    const uint32_t *path,
                                                    size_t path_len,
                                                    cx_md_t hashID,
                                                    const uint8_t *hash,
                                                    size_t hash_len,
                                                    uint8_t *sig,
                                                    size_t *sig_len,
                                                    unsigned char *seed,
                                                    size_t seed_len) {
    (void) derivation_mode;
    (void) curve;
    (void) path;
    (void) path_len;
    (void) hashID;
    (void) seed;
    (void) seed_len;
    g_sign_count++;
    memcpy(g_signed_msg, hash, hash_len);
    g_signed_len = hash_len;
    memset(sig, 0xAB, ED25519_SIG_LEN);
    *sig_len = ED25519_SIG_LEN;
    return CX_OK;
}

// ---- helpers ----
static const uint8_t PATH[] = {5,                       // depth
                               0x80, 0x00, 0x00, 0x2C,  // 44'
                               0xCC, 0x53, 0x53, 0x48,  // 1280529224' ("LSSH")
                               0x80, 0x00, 0x00, 0x00,  // 0'
                               0x80, 0x00, 0x00, 0x00,  // 0'
                               0x80, 0x00, 0x00, 0x00};  // 0'
static const uint8_t ETH_PATH[] = {5,                       // depth
                                   0x80, 0x00, 0x00, 0x2C,  // 44'
                                   0x80, 0x00, 0x00, 0x3C,  // 60'
                                   0x80, 0x00, 0x00, 0x00,  // 0'
                                   0x00, 0x00, 0x00, 0x00,  // 0
                                   0x00, 0x00, 0x00, 0x00};  // 0
static const uint8_t MSG[] = "message shown to the user";
static const uint8_t EXTRA[] = "attacker data";

static uint16_t send_chunk(const uint8_t *data, size_t len, uint8_t chunk, bool more) {
    uint8_t cdata[UINT8_MAX] = {0};
    memcpy(cdata, data, len);
    buffer_t buf = {.ptr = cdata, .size = len, .offset = 0};
    g_last_sw = 0;
    handler_sign_ssh(&buf, chunk, more);
    return g_last_sw;
}

static uint16_t dispatch(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t lc) {
    uint8_t cdata[UINT8_MAX] = {0};
    if (data != NULL) {
        memcpy(cdata, data, lc);
    }
    command_t cmd = {.cla = CLA, .ins = ins, .p1 = p1, .p2 = p2, .lc = lc, .data = cdata};
    g_last_sw = 0;
    apdu_dispatcher(&cmd);
    return g_last_sw;
}

// Path + one message chunk: the approval screen is displayed
static void start_flow_until_prompt(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, send_chunk(PATH, sizeof(PATH), 0, true));
    g_last_sw = 0;
    send_chunk(MSG, sizeof(MSG), 1, false);
    TEST_ASSERT_EQUAL_HEX16(0, g_last_sw);  // no answer until the user decides
    TEST_ASSERT_EQUAL(1, g_prompt_count);
    TEST_ASSERT_EQUAL(SSH_STATE_WAITING_APPROVAL, G_context.state);
}

void setUp(void) {
    Mockio_Init();
    Mockget_version_Init();
    Mockget_app_name_Init();
    Mockget_public_key_Init();
    io_send_response_buffers_StubWithCallback(io_send_cb);
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    g_last_len = 0;
    g_sw_count = 0;
    g_choice_cb = NULL;
    g_prompt_count = 0;
    g_sign_count = 0;
    g_signed_len = 0;
}

void tearDown(void) {
    Mockio_Verify();
    Mockio_Destroy();
    Mockget_version_Verify();
    Mockget_version_Destroy();
    Mockget_app_name_Verify();
    Mockget_app_name_Destroy();
    Mockget_public_key_Verify();
    Mockget_public_key_Destroy();
}

// ---- tests ----
void test_approve_signs_exact_message(void) {
    start_flow_until_prompt();
    g_choice_cb(true);
    TEST_ASSERT_EQUAL(1, g_sign_count);
    TEST_ASSERT_EQUAL(sizeof(MSG), g_signed_len);
    TEST_ASSERT_EQUAL_MEMORY(MSG, g_signed_msg, sizeof(MSG));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, g_last_sw);
    TEST_ASSERT_EQUAL(ED25519_SIG_LEN, g_last_len);
    TEST_ASSERT_EQUAL(SSH_STATE_NONE, G_context.state);
}

void test_reject_does_not_sign(void) {
    start_flow_until_prompt();
    g_choice_cb(false);
    TEST_ASSERT_EQUAL(0, g_sign_count);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, g_last_sw);
    TEST_ASSERT_EQUAL(SSH_STATE_NONE, G_context.state);
}

// Handler level: no chunk can be appended while the prompt is displayed
void test_handler_refuses_append_during_prompt(void) {
    start_flow_until_prompt();
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, send_chunk(EXTRA, sizeof(EXTRA), 2, false));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, send_chunk(PATH, sizeof(PATH), 0, true));
    TEST_ASSERT_EQUAL(sizeof(MSG), G_context.ssh_info.message_len);
    TEST_ASSERT_EQUAL(1, g_prompt_count);

    g_choice_cb(true);
    TEST_ASSERT_EQUAL(1, g_sign_count);
    TEST_ASSERT_EQUAL(sizeof(MSG), g_signed_len);
    TEST_ASSERT_EQUAL_MEMORY(MSG, g_signed_msg, sizeof(MSG));
}

// Dispatcher level: every command is refused while the prompt is displayed,
// including GET_PUBLIC_KEY which would otherwise wipe the context
void test_dispatcher_refuses_all_commands_during_prompt(void) {
    start_flow_until_prompt();

    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(SIGN_SSH, 2, 0x00, EXTRA, sizeof(EXTRA)));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(SIGN_SSH, 0, 0x80, PATH, sizeof(PATH)));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(GET_PUBLIC_KEY, 0, 0, PATH, sizeof(PATH)));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(GET_VERSION, 0, 0, NULL, 0));
    // handler_get_public_key / handler_get_version mocks have no expectations:
    // CMock fails the test if they were called

    TEST_ASSERT_EQUAL(SSH_STATE_WAITING_APPROVAL, G_context.state);
    TEST_ASSERT_EQUAL(sizeof(MSG), G_context.ssh_info.message_len);
    TEST_ASSERT_EQUAL_MEMORY(MSG, G_context.ssh_info.message, sizeof(MSG));

    g_choice_cb(true);
    TEST_ASSERT_EQUAL_MEMORY(MSG, g_signed_msg, sizeof(MSG));
    TEST_ASSERT_EQUAL(sizeof(MSG), g_signed_len);

    // After the answer, commands are accepted again
    handler_get_version_ExpectAndReturn(0);
    dispatch(GET_VERSION, 0, 0, NULL, 0);
}

// If the context is not in the approval state when the user answers, never sign
void test_choice_without_pending_flow_does_not_sign(void) {
    start_flow_until_prompt();
    G_context.state = SSH_STATE_NONE;  // simulate a context change behind the screen
    g_choice_cb(true);
    TEST_ASSERT_EQUAL(0, g_sign_count);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, g_last_sw);
}

void test_chunks_must_be_sequential(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, send_chunk(PATH, sizeof(PATH), 0, true));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, send_chunk(MSG, sizeof(MSG), 2, true));
    TEST_ASSERT_EQUAL(SSH_STATE_NONE, G_context.state);  // flow aborted

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, send_chunk(PATH, sizeof(PATH), 0, true));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, send_chunk(MSG, sizeof(MSG), 1, true));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, send_chunk(MSG, sizeof(MSG), 1, false));
    TEST_ASSERT_EQUAL(SSH_STATE_NONE, G_context.state);
    TEST_ASSERT_EQUAL(0, g_prompt_count);
}

void test_data_without_path_refused(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, send_chunk(MSG, sizeof(MSG), 1, false));
    TEST_ASSERT_EQUAL(0, g_prompt_count);
}

void test_foreign_path_refused(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, send_chunk(ETH_PATH, sizeof(ETH_PATH), 0, true));
    TEST_ASSERT_EQUAL(SSH_STATE_NONE, G_context.state);
    TEST_ASSERT_EQUAL(0, G_context.bip32_path_len);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, send_chunk(MSG, sizeof(MSG), 1, false));
    TEST_ASSERT_EQUAL(0, g_prompt_count);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_approve_signs_exact_message);
    RUN_TEST(test_reject_does_not_sign);
    RUN_TEST(test_handler_refuses_append_during_prompt);
    RUN_TEST(test_dispatcher_refuses_all_commands_during_prompt);
    RUN_TEST(test_choice_without_pending_flow_does_not_sign);
    RUN_TEST(test_chunks_must_be_sequential);
    RUN_TEST(test_data_without_path_refused);
    RUN_TEST(test_foreign_path_refused);
    return UNITY_END();
}

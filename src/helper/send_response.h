#pragma once

/**
 * Helper to send APDU response with the ed25519 public key held in
 * G_context.pk_info, encoded as in RFC 8032 (32 bytes).
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_pubkey(void);

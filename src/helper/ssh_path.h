#pragma once

#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t

/**
 * Check that a BIP32 path is under this app's prefix m/44'/1280529224'
 * and that every level is hardened.
 *
 * @param[in] path     BIP32 path.
 * @param[in] path_len Number of levels in path.
 *
 * @return true if the app may derive a key at this path, false otherwise.
 *
 */
bool ssh_path_is_allowed(const uint32_t *path, size_t path_len);

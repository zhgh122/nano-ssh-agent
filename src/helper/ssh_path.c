#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t

#include "ssh_path.h"
#include "constants.h"

bool ssh_path_is_allowed(const uint32_t *path, size_t path_len) {
    if (path == NULL || path_len <= SSH_PATH_PREFIX_LEN) {
        return false;
    }
    if (path[0] != SSH_PATH_PURPOSE || path[1] != SSH_PATH_COIN_TYPE) {
        return false;
    }
    for (size_t i = SSH_PATH_PREFIX_LEN; i < path_len; i++) {
        if ((path[i] & 0x80000000u) == 0) {
            return false;
        }
    }
    return true;
}

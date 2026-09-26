from struct import unpack

ED25519_PUBKEY_LEN: int = 32
ED25519_SIG_LEN: int = 64


# remainder, data
def pop_sized_buf_from_buffer(buffer: bytes, size: int) -> tuple[bytes, bytes]:
    return buffer[size:], buffer[0:size]


# remainder, data_len, data
def pop_size_prefixed_buf_from_buf(buffer: bytes) -> tuple[bytes, int, bytes]:
    data_len = buffer[0]
    return buffer[1 + data_len :], data_len, buffer[1 : data_len + 1]


# Unpack from response:
# response = app_name (var)
def unpack_get_app_name_response(response: bytes) -> str:
    return response.decode("ascii")


# Unpack from response:
# response = MAJOR (1)
#            MINOR (1)
#            PATCH (1)
def unpack_get_version_response(response: bytes) -> tuple[int, int, int]:
    assert len(response) == 3
    major, minor, patch = unpack("BBB", response)
    return (major, minor, patch)


# Unpack from response:
# response = format_id (1)
#            app_name_raw_len (1)
#            app_name_raw (var)
#            version_raw_len (1)
#            version_raw (var)
#            unused_len (1)
#            unused (var)
def unpack_get_app_and_version_response(response: bytes) -> tuple[str, str]:
    response, _ = pop_sized_buf_from_buffer(response, 1)
    response, _, app_name_raw = pop_size_prefixed_buf_from_buf(response)
    response, _, version_raw = pop_size_prefixed_buf_from_buf(response)
    response, _, _ = pop_size_prefixed_buf_from_buf(response)

    assert len(response) == 0

    return app_name_raw.decode("ascii"), version_raw.decode("ascii")


# Unpack from response:
# response = ed25519 public key, RFC 8032 encoding (32)
def unpack_get_public_key_response(response: bytes) -> bytes:
    assert len(response) == ED25519_PUBKEY_LEN
    return response


# Unpack from response:
# response = ed25519 signature (64)
def unpack_sign_ssh_response(response: bytes) -> bytes:
    assert len(response) == ED25519_SIG_LEN
    return response

from collections.abc import Generator
from contextlib import contextmanager
from enum import IntEnum

from ragger.backend.interface import RAPDU, BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import StatusWords

MAX_APDU_LEN: int = 255

# Maximum message size accepted by SIGN_SSH (MAX_SSH_MESSAGE_LEN in src/constants.h)
MAX_SSH_MESSAGE_LEN: int = 510

CLA: int = 0xE0

# Derivation prefix reserved for the app (SSH_PATH_* in src/constants.h):
# 1280529224 = 0x4C535348 = ASCII "LSSH"
SSH_PATH_PREFIX: str = "m/44'/1280529224'"
SSH_DEFAULT_PATH: str = f"{SSH_PATH_PREFIX}/0'/0'/0'"


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class InsType(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_PUBLIC_KEY = 0x05
    SIGN_SSH = 0x10


Errors = StatusWords


def split_message(message: bytes, max_size: int) -> list[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


class SshCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=0xB0,  # specific CLA for BOLOS
            ins=0x01,  # specific INS for get_app_and_version
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=b"",
        )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_START, p2=P2.P2_LAST, data=b"")

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_START, p2=P2.P2_LAST, data=b"")

    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=pack_derivation_path(path),
        )

    def sign_ssh_start(self, path: str) -> RAPDU:
        """Send chunk 0 (derivation path) of SIGN_SSH."""
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_SSH,
            p1=P1.P1_START,
            p2=P2.P2_MORE,
            data=pack_derivation_path(path),
        )

    def sign_ssh_chunk(self, idx: int, data: bytes, last: bool) -> RAPDU:
        """Send one message chunk of SIGN_SSH synchronously (no user interaction expected)."""
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_SSH,
            p1=idx,
            p2=P2.P2_LAST if last else P2.P2_MORE,
            data=data,
        )

    # sign_ssh sends the message and yields while the device waits for user approval,
    # so that the caller can perform the navigation.
    @contextmanager
    def sign_ssh(self, path: str, message: bytes) -> Generator[None, None, None]:
        self.sign_ssh_start(path)
        chunks = split_message(message, MAX_APDU_LEN)
        idx: int = P1.P1_START + 1

        for chunk in chunks[:-1]:
            self.sign_ssh_chunk(idx, chunk, last=False)
            idx += 1

        with self.backend.exchange_async(
            cla=CLA, ins=InsType.SIGN_SSH, p1=idx, p2=P2.P2_LAST, data=chunks[-1]
        ) as response:
            yield response

    # Retrieve the last asynchronous response from the backend
    def get_async_response(self) -> RAPDU | None:
        return self.backend.last_async_response

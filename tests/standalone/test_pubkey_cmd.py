import pytest
from ragger.backend.interface import BackendInterface
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode, pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.ssh_command_sender import (
    CLA,
    P1,
    P2,
    SSH_DEFAULT_PATH,
    SSH_PATH_PREFIX,
    Errors,
    InsType,
    SshCommandSender,
)
from application_client.ssh_response_unpacker import unpack_get_public_key_response


# GET_PUBLIC_KEY returns the SLIP-10 ed25519 public key (32 bytes) without user interaction
def test_get_public_key(backend: BackendInterface) -> None:
    path_list = [
        SSH_DEFAULT_PATH,
        f"{SSH_PATH_PREFIX}/0'/0'/1'",
        f"{SSH_PATH_PREFIX}/911'",
        f"{SSH_PATH_PREFIX}/2147483647'/0'/0'/0'/0'/0'/0'/0'",
    ]
    client = SshCommandSender(backend)
    for path in path_list:
        public_key = unpack_get_public_key_response(client.get_public_key(path=path).data)
        ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Ed25519Slip, path=path)
        # ragger prefixes ed25519 keys with a 0x00 byte
        assert public_key.hex() == ref_public_key[2:]


# SLIP-10 ed25519 only supports hardened derivation: the app must fail, not return a key
def test_get_public_key_non_hardened_path(backend: BackendInterface) -> None:
    client = SshCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_public_key(path=f"{SSH_PATH_PREFIX}/0'/0'/0")
    assert e.value.status == Errors.SWO_INCORRECT_DATA


# The app may only derive under its own prefix: keys of wallet apps are out of reach
def test_get_public_key_foreign_paths(backend: BackendInterface) -> None:
    foreign_paths = [
        "m/44'/1'/0'/0'/0'",  # testnet coin type used by earlier versions
        "m/44'/0'/0'/0'/0'",  # bitcoin
        "m/44'/60'/0'/0'/0'",  # ethereum
        "m/44'/535348'/0'/0'/0'",  # Ledger SSH/PGP agent app
        "m/13'/0'/0'/0'/0'",  # SLIP-13
        SSH_PATH_PREFIX,  # prefix alone
    ]
    client = SshCommandSender(backend)
    for path in foreign_paths:
        with pytest.raises(ExceptionRAPDU) as e:
            client.get_public_key(path=path)
        assert e.value.status == Errors.SWO_INCORRECT_DATA, path


# The on-screen confirmation mode of the boilerplate was removed: P1 must be 0
def test_get_public_key_bad_p1(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START + 1,
            p2=P2.P2_LAST,
            data=pack_derivation_path(SSH_DEFAULT_PATH),
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_get_public_key_malformed_path(backend: BackendInterface) -> None:
    path = pack_derivation_path(SSH_DEFAULT_PATH)
    bad_payloads = [
        b"",  # no data at all
        path[:-1],  # truncated last index
        path + b"\x00",  # trailing byte
        bytes([11]) + path[1:],  # declared depth larger than MAX_BIP32_PATH
    ]
    for data in bad_payloads:
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(cla=CLA, ins=InsType.GET_PUBLIC_KEY, p1=P1.P1_START, p2=P2.P2_LAST, data=data)
        assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH, data.hex()

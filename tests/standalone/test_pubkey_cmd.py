import pytest
from ragger.backend.interface import BackendInterface
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode, pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.ssh_command_sender import CLA, P1, P2, Errors, InsType, SshCommandSender
from application_client.ssh_response_unpacker import unpack_get_public_key_response


# GET_PUBLIC_KEY returns the SLIP-10 ed25519 public key (32 bytes) without user interaction
def test_get_public_key(backend: BackendInterface) -> None:
    path_list = [
        "m/44'/1'/0'/0'/0'",
        "m/44'/1'/0'/0'/1'",
        "m/44'/1'/911'/0'/0'",
        "m/44'/1'/2147483647'/0'/0'/0'/0'/0'/0'/0'",
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
        client.get_public_key(path="m/44'/1'/0'/0/0")
    assert e.value.status == Errors.SWO_INCORRECT_DATA


# The on-screen confirmation mode of the boilerplate was removed: P1 must be 0
def test_get_public_key_bad_p1(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START + 1,
            p2=P2.P2_LAST,
            data=pack_derivation_path("m/44'/1'/0'/0'/0'"),
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_get_public_key_malformed_path(backend: BackendInterface) -> None:
    path = pack_derivation_path("m/44'/1'/0'/0'/0'")
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

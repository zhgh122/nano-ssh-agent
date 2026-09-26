import os

import pytest
from ledgered.devices import Device
from ragger.backend.interface import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID

from application_client.ssh_command_sender import (
    MAX_APDU_LEN,
    MAX_SSH_MESSAGE_LEN,
    P1,
    Errors,
    SshCommandSender,
)
from application_client.ssh_response_unpacker import (
    unpack_get_public_key_response,
    unpack_sign_ssh_response,
)

from .utils import check_signature_validity

PATH: str = "m/44'/1'/0'/0'/0'"


def _answer_prompt(device: Device, navigator: Navigator, snapshots_path: str, test_name: str, approve: bool) -> None:
    if device.is_nano:
        navigator.navigate_until_text_and_compare(
            NavInsID.RIGHT_CLICK,
            [NavInsID.BOTH_CLICK],
            "Approve" if approve else "Reject",
            snapshots_path,
            test_name,
        )
    else:
        navigator.navigate_and_compare(
            snapshots_path,
            test_name,
            [NavInsID.USE_CASE_CHOICE_CONFIRM if approve else NavInsID.USE_CASE_CHOICE_REJECT],
        )


def _sign_and_approve(
    backend: BackendInterface,
    device: Device,
    navigator: Navigator,
    snapshots_path: str,
    test_name: str,
    message: bytes,
) -> None:
    client = SshCommandSender(backend)
    public_key = unpack_get_public_key_response(client.get_public_key(path=PATH).data)

    with client.sign_ssh(path=PATH, message=message):
        _answer_prompt(device, navigator, snapshots_path, test_name, approve=True)

    signature = unpack_sign_ssh_response(client.get_async_response().data)
    assert check_signature_validity(public_key, signature, message)


# Message fits in one APDU
def test_sign_ssh_short(
    backend: BackendInterface, device: Device, navigator: Navigator, default_screenshot_path: str, test_name: str
) -> None:
    _sign_and_approve(backend, device, navigator, default_screenshot_path, test_name, os.urandom(100))


# Largest accepted message, spread over two APDUs
def test_sign_ssh_max_length(
    backend: BackendInterface, device: Device, navigator: Navigator, default_screenshot_path: str, test_name: str
) -> None:
    _sign_and_approve(backend, device, navigator, default_screenshot_path, test_name, os.urandom(MAX_SSH_MESSAGE_LEN))


def test_sign_ssh_refused(
    backend: BackendInterface, device: Device, navigator: Navigator, default_screenshot_path: str, test_name: str
) -> None:
    client = SshCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_ssh(path=PATH, message=b"user refuses this"):
            _answer_prompt(device, navigator, default_screenshot_path, test_name, approve=False)
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED

    # The context has been wiped: continuing the flow without a new path must fail
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_ssh_chunk(P1.P1_START + 1, b"more", last=True)
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED


def test_sign_ssh_too_long(backend: BackendInterface) -> None:
    client = SshCommandSender(backend)
    client.sign_ssh_start(PATH)
    client.sign_ssh_chunk(1, bytes(MAX_APDU_LEN), last=False)
    client.sign_ssh_chunk(2, bytes(MAX_SSH_MESSAGE_LEN - MAX_APDU_LEN), last=False)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_ssh_chunk(3, b"\x00", last=True)
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH

    # The context has been wiped after the error
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_ssh_chunk(1, b"\x00", last=True)
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED


def test_sign_ssh_data_before_path(backend: BackendInterface) -> None:
    client = SshCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_ssh_chunk(1, b"no path sent", last=True)
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED


def test_sign_ssh_bad_p1_p2(backend: BackendInterface) -> None:
    client = SshCommandSender(backend)
    # chunk 0 must announce more data
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_ssh_chunk(P1.P1_START, b"\x00", last=True)
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2
    # chunk index above P1_MAX
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_ssh_chunk(P1.P1_MAX + 1, b"\x00", last=True)
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_sign_ssh_malformed_path(backend: BackendInterface) -> None:
    client = SshCommandSender(backend)
    path = pack_derivation_path(PATH)
    zero_depth = bytes([0])
    for data in [path[:-1], path + b"\x00", zero_depth]:
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_ssh_chunk(P1.P1_START, data, last=False)
        assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH, data.hex()

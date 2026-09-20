import numpy as np

from stegano_utils import hide_message, reveal_message, encode_msg


def test_password_is_not_embedded_in_payload():
    image = np.zeros((32, 32, 3), dtype=np.uint8)
    password = "StrongPass!123"
    msg = "Secret message"

    payload = encode_msg(msg, password)

    assert password.encode("utf-8") not in payload
    assert b"::" not in payload
    assert payload.startswith(b"AILSB2")


def test_encrypt_and_decrypt_round_trip():
    image = np.zeros((32, 32, 3), dtype=np.uint8)
    password = "StrongPass!123"
    msg = "This is a hidden message"

    stego = hide_message(image, msg, password)
    recovered = reveal_message(stego, password)

    assert recovered == msg


def test_wrong_password_fails():
    image = np.zeros((32, 32, 3), dtype=np.uint8)
    password = "StrongPass!123"
    msg = "Another secret"

    stego = hide_message(image, msg, password)
    recovered = reveal_message(stego, "WrongPass")

    assert recovered is None

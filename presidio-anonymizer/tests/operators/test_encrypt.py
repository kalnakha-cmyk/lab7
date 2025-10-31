from unittest import mock
import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators.operator import OperatorType


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text
    mock_encrypt.assert_called_once()


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text
    mock_encrypt.assert_called_once()


def test_given_verifying_a_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_a_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})


# ✅ Mock the method that determines key size validity to trigger the error path
@mock.patch.object(AESCipher, "is_valid_key_size", return_value=False)
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size):
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})
    mock_is_valid_key_size.assert_called_once()


def test_operator_name():
    """Test that operator_name returns 'encrypt'."""
    operator = Encrypt()
    assert operator.operator_name() == "encrypt"


def test_operator_type():
    """Test that operator_type returns OperatorType.Anonymize."""
    operator = Encrypt()
    assert operator.operator_type() == OperatorType.Anonymize


import pytest
from presidio_anonymizer.operators import Encrypt


@pytest.mark.parametrize(
    "key",
    [
        "A" * 16,   # 128-bit string key
        "B" * 24,   # 192-bit string key
        "C" * 32,   # 256-bit string key
        b"A" * 16,  # 128-bit bytes key
        b"B" * 24,  # 192-bit bytes key
        b"C" * 32,  # 256-bit bytes key
    ],
)
def test_valid_keys(key):
    """Test that Encrypt.validate() succeeds for valid AES key sizes."""
    encryptor = Encrypt()
    # Should not raise InvalidParamError
    encryptor.validate(params={"key": key})

import pytest
from analyzers.encoding import auto_decode, decode_base64, decode_hex, decode_url


class TestEncoding:
    def test_decode_base64_valid(self):
        result = decode_base64("aGVsbG8gd29ybGQ=")
        assert result["success"] is True
        assert result["result"] == "hello world"

    def test_decode_base64_invalid(self):
        result = decode_base64("not-valid!!!")
        assert result["success"] is False

    def test_decode_hex_valid(self):
        result = decode_hex("48656c6c6f")
        assert result["success"] is True
        assert result["result"] == "Hello"

    def test_decode_hex_with_spaces(self):
        result = decode_hex("48 65 6c 6c 6f")
        assert result["success"] is True
        assert result["result"] == "Hello"

    def test_decode_url(self):
        result = decode_url("hello%20world%21")
        assert result["success"] is True
        assert result["result"] == "hello world!"

    def test_auto_decode_base64(self):
        result = auto_decode("aGVsbG8=")
        assert "Base64" in result["chain"]

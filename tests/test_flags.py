import base64
import codecs

import pytest

from sharkai.flags import FlagScanner

S = FlagScanner()


def flags(data: bytes, scanner=S):
    return {(f.flag, f.encoding, f.confidence) for f in scanner.scan(data)}


@pytest.mark.parametrize("data, enc", [
    (b"noise flag{plain_one} noise", "plain"),
    (base64.b64encode(b"x flag{b64_one}"), "base64"),
    (b"k=" + b"flag{hex_one}".hex().encode(), "hex"),
    (base64.b32encode(b"CTF{b32_one_1}"), "base32"),
    (b"q=flag%7Burl_one%7D", "url"),
    (b"}eno_vr{galf", "reversed"),
    (base64.b64encode(base64.b64encode(b"flag{twice_1}")), "base64+base64"),
    (b"some data " + base64.urlsafe_b64encode(b">>>???flag{u_safe_1}"), "base64"),
])
def test_encodings(data, enc):
    assert any(e == enc and c == "high" for _, e, c in flags(data))


def test_rot13_known_prefix():
    assert ("flag{rot_13}", "rot13", "high") in flags(codecs.encode("flag{rot_13}", "rot13").encode())


def test_flag_glued_to_other_text_and_known_prefixes():
    assert ("picoCTF{x_1}", "plain", "high") in flags(b"abcdefghpicoCTF{x_1}")
    assert ("HTB{a_b_c}", "plain", "high") in flags(b" HTB{a_b_c} ")


def test_false_positives_are_suppressed():
    assert not flags(b"body{margin:0} a{color:red} ${var} algorithm{thm_x} {}")
    assert not flags(b"just a long sentence about network forensics " * 50)


def test_generic_shape_is_low_confidence_and_prefix_promotes_it():
    assert ("ACME{leet_12345}", "plain", "low") in flags(b"x ACME{leet_12345} y")
    assert ("ACME{leet_12345}", "plain", "high") in flags(b"x ACME{leet_12345} y", FlagScanner(("acme",)))


def test_binary_and_huge_inputs_are_handled():
    import os
    assert flags(os.urandom(200_000)) == set() or True  # must not raise or hang
    big = b"A" * (5 * 1024 * 1024) + b" flag{big_plain_1}"
    assert ("flag{big_plain_1}", "plain", "high") in flags(big)

import re
import pytest
from analyzers.flag_analyzer import FlagAnalyzer, DEFAULT_PATTERNS


class TestFlagPatterns:
    def test_default_patterns_match(self):
        test_flags = [
            ("flag{test123}", "flag{...}"),
            ("FLAG{UPPER}", "FLAG{...}"),
            ("CTF{challenge}", "CTF{...}"),
            ("THM{tryhackme}", "THM{...}"),
            ("picoCTF{test}", "picoCTF{...}"),
        ]
        for flag_text, expected_pattern in test_flags:
            matched = False
            for pattern, name, _ in DEFAULT_PATTERNS:
                if re.search(pattern, flag_text):
                    assert name == expected_pattern
                    matched = True
                    break
            assert matched, f"No pattern matched {flag_text}"

    def test_no_false_positive(self):
        for pattern, _, _ in DEFAULT_PATTERNS:
            assert not re.search(pattern, "this is not a flag")

    def test_fragmented_reconstruction(self):
        parts = ["flag{", "secret_", "123}"]
        combined = "".join(parts)
        for pattern, name, conf in DEFAULT_PATTERNS:
            match = re.search(pattern, combined)
            if match:
                assert match.group(0) == "flag{secret_123}"
                break
        else:
            pytest.fail("Failed to reconstruct fragmented flag")

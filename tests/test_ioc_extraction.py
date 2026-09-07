import pytest
from analyzers.ioc_analyzer import IocAnalyzer


class TestIocExtraction:
    def test_ipv4_pattern(self):
        analyzer = IocAnalyzer()
        text = "Contact 192.168.1.1 for details"
        matches = analyzer.IPV4_PATTERN.findall(text)
        assert "192.168.1.1" in matches

    def test_email_pattern(self):
        analyzer = IocAnalyzer()
        text = "Email admin@example.com"
        matches = analyzer.EMAIL_PATTERN.findall(text)
        assert "admin@example.com" in matches

    def test_md5_pattern(self):
        analyzer = IocAnalyzer()
        hash_val = "d41d8cd98f00b204e9800998ecf8427e"
        matches = analyzer.MD5_PATTERN.findall(hash_val)
        assert hash_val in matches

    def test_export_csv(self):
        analyzer = IocAnalyzer()
        iocs = [
            {"type": "ipv4", "value": "10.0.0.1", "source": "test"},
            {"type": "domain", "value": "example.com", "source": "dns"},
        ]
        csv = analyzer.export_csv(iocs)
        assert "type,value,source" in csv
        assert "10.0.0.1" in csv

    def test_export_txt(self):
        analyzer = IocAnalyzer()
        iocs = [{"type": "ipv4", "value": "10.0.0.1", "source": "test"}]
        txt = analyzer.export_txt(iocs)
        assert "IPV4" in txt
        assert "10.0.0.1" in txt

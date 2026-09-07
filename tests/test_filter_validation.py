import pytest
from app.core.security import validate_display_filter


class TestFilterValidation:
    def test_simple_protocol(self):
        valid, err = validate_display_filter("tcp")
        assert valid is True

    def test_compound_filter(self):
        valid, err = validate_display_filter("tcp.port == 80")
        assert valid is True

    def test_http_post_filter(self):
        valid, err = validate_display_filter("http.request.method == POST")
        assert valid is True

    def test_rejects_shell_injection(self):
        valid, err = validate_display_filter("tcp; rm -rf /")
        assert valid is False

    def test_rejects_pipe(self):
        valid, err = validate_display_filter("tcp | cat /etc/passwd")
        assert valid is False

    def test_rejects_backtick(self):
        valid, err = validate_display_filter("tcp `whoami`")
        assert valid is False

    def test_empty_filter(self):
        valid, err = validate_display_filter("")
        assert valid is True

    def test_ip_filter(self):
        valid, err = validate_display_filter("ip.addr == 10.10.10.5")
        assert valid is True

    def test_dns_filter(self):
        valid, err = validate_display_filter('dns.qry.name contains "example"')
        assert valid is True

    def test_too_long_filter(self):
        valid, err = validate_display_filter("a" * 3000)
        assert valid is False

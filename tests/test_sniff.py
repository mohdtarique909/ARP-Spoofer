"""Tests for the HTTP sniffer's URL extraction and credential detection."""

import scapy.all as scapy
from scapy.layers import http

from arpspoofer import sniff


def _http_request(host=b"example.com", path=b"/login", method=b"POST", body=None):
    packet = scapy.IP() / scapy.TCP() / http.HTTPRequest(
        Host=host, Path=path, Method=method
    )
    if body is not None:
        packet = packet / scapy.Raw(load=body)
    return packet


class TestUrl:
    def test_reconstructs_full_url(self):
        assert sniff.get_url(_http_request()) == "example.com/login"


class TestCredentials:
    def test_flags_body_with_password_field(self):
        packet = _http_request(body=b"username=admin&password=hunter2")
        assert sniff.get_credentials(packet) == "username=admin&password=hunter2"

    def test_ignores_innocuous_body(self):
        packet = _http_request(body=b"q=cats&page=2")
        assert sniff.get_credentials(packet) is None

    def test_returns_none_without_payload(self):
        assert sniff.get_credentials(_http_request()) is None

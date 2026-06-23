"""Tests for validation and MAC resolution (scapy is mocked - no real packets)."""

from unittest import mock

import pytest

from arpspoofer import utils


class TestValidation:
    def test_valid_ip_passes_through(self):
        assert utils.valid_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ip_rejects_garbage(self):
        with pytest.raises(ValueError):
            utils.valid_ip("not-an-ip")

    def test_valid_ip_rejects_out_of_range(self):
        with pytest.raises(ValueError):
            utils.valid_ip("999.1.1.1")

    def test_valid_network_normalises(self):
        assert utils.valid_network("192.168.1.0/24") == "192.168.1.0/24"

    def test_valid_network_rejects_bad_cidr(self):
        with pytest.raises(ValueError):
            utils.valid_network("192.168.1.0/99")


class TestGetMac:
    def test_returns_mac_when_host_answers(self):
        reply = mock.Mock()
        reply.hwsrc = "aa:bb:cc:dd:ee:ff"
        answered = [(mock.Mock(), reply)]  # srp returns (answered, unanswered)
        with mock.patch.object(utils.scapy, "srp", return_value=(answered, [])):
            assert utils.get_mac("192.168.1.5") == "aa:bb:cc:dd:ee:ff"

    def test_returns_none_when_no_reply(self):
        # Empty answered list across all retries -> None, never an IndexError.
        with mock.patch.object(utils.scapy, "srp", return_value=([], [])):
            assert utils.get_mac("192.168.1.99", retries=2) is None

    def test_retries_until_success(self):
        reply = mock.Mock()
        reply.hwsrc = "11:22:33:44:55:66"
        side_effects = [([], []), ([(mock.Mock(), reply)], [])]
        with mock.patch.object(utils.scapy, "srp", side_effect=side_effects):
            assert utils.get_mac("192.168.1.5", retries=2) == "11:22:33:44:55:66"

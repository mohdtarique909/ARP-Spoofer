"""Tests for argument parsing, especially shared-flag positioning."""

import pytest

from arpspoofer.cli import build_parser


class TestSharedFlags:
    def test_iface_after_subcommand(self):
        # The bug we fixed: -i must be accepted AFTER the subcommand.
        args = build_parser().parse_args(
            ["spoof", "-t", "192.168.1.5", "-g", "192.168.1.1", "-i", "eth0"]
        )
        assert args.iface == "eth0"
        assert args.command == "spoof"

    def test_iface_before_subcommand_still_works(self):
        args = build_parser().parse_args(
            ["-i", "eth0", "spoof", "-t", "192.168.1.5", "-g", "192.168.1.1"]
        )
        assert args.iface == "eth0"

    def test_verbose_after_subcommand(self):
        args = build_parser().parse_args(["scan", "192.168.1.0/24", "-v"])
        assert args.verbose is True


class TestValidation:
    def test_rejects_invalid_ip(self, capsys):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["spoof", "-t", "999.1.1.1", "-g", "192.168.1.1"])
        assert "not a valid IP address" in capsys.readouterr().err

    def test_rejects_invalid_cidr(self, capsys):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["scan", "192.168.1.0/99"])
        assert "not a valid network" in capsys.readouterr().err


class TestSubcommands:
    def test_sniff_command_parses(self):
        args = build_parser().parse_args(["sniff", "-i", "eth0", "--count", "5"])
        assert args.command == "sniff"
        assert args.count == 5

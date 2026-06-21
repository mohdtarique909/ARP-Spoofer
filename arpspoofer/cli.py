"""Command-line interface dispatching to spoof / detect / scan / restore."""

import argparse
import sys

from . import __version__, detect, scan, spoof
from .utils import setup_logging, valid_ip, valid_network


def _ip_arg(value):
    try:
        return valid_ip(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _network_arg(value):
    try:
        return valid_network(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="arpspoofer",
        description="Educational ARP toolkit: spoof, detect, scan, restore. "
        "Use only on networks you are authorized to test.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    parser.add_argument("--logfile", help="also write logs to this file")
    parser.add_argument("-i", "--iface", help="network interface to use (e.g. eth0)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_spoof = sub.add_parser("spoof", help="run a MITM ARP poisoning attack")
    p_spoof.add_argument("-t", "--target", required=True, type=_ip_arg, help="victim IP")
    p_spoof.add_argument("-g", "--gateway", required=True, type=_ip_arg, help="gateway/router IP")
    p_spoof.add_argument("--interval", type=float, default=2, help="seconds between bursts (default 2)")
    p_spoof.add_argument(
        "--no-forward",
        action="store_true",
        help="do NOT auto-enable IP forwarding (this causes a DoS, not a MITM)",
    )

    p_detect = sub.add_parser("detect", help="detect ARP spoofing on the network")
    p_detect.add_argument("--count", type=int, default=0, help="stop after N packets (0 = forever)")

    p_scan = sub.add_parser("scan", help="discover live hosts (IP + MAC)")
    p_scan.add_argument("network", type=_network_arg, help="CIDR to scan, e.g. 192.168.1.0/24")
    p_scan.add_argument("--timeout", type=float, default=2, help="reply timeout in seconds")

    p_restore = sub.add_parser("restore", help="manually restore two hosts' ARP tables")
    p_restore.add_argument("-t", "--target", required=True, type=_ip_arg)
    p_restore.add_argument("-g", "--gateway", required=True, type=_ip_arg)

    return parser


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except ValueError as exc:  # raised by valid_ip / valid_network
        parser.error(str(exc))

    setup_logging(verbose=args.verbose, logfile=args.logfile)

    if args.command == "spoof":
        return spoof.run(
            args.target,
            args.gateway,
            iface=args.iface,
            interval=args.interval,
            forward=not args.no_forward,
        )
    if args.command == "detect":
        return detect.run(iface=args.iface, count=args.count)
    if args.command == "scan":
        return scan.run(args.network, iface=args.iface, timeout=args.timeout)
    if args.command == "restore":
        spoof.restore(args.target, args.gateway, iface=args.iface)
        spoof.restore(args.gateway, args.target, iface=args.iface)
        return 0
    parser.error("unknown command")


if __name__ == "__main__":
    sys.exit(main())

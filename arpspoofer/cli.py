"""Command-line interface dispatching to spoof / detect / scan / sniff / restore."""

import argparse
import sys

from . import __version__, detect, scan, sniff, spoof
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
    # Shared flags live on a parent parser so they work BOTH before the
    # subcommand (arpspoofer -i eth0 spoof ...) and after it
    # (arpspoofer spoof ... -i eth0), which is what most people type.
    # The parent copies use default=SUPPRESS so that when a flag is given
    # before the subcommand, the subparser doesn't clobber it with its default.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v", "--verbose", action="store_true",
        default=argparse.SUPPRESS, help="enable debug logging",
    )
    common.add_argument("--logfile", default=argparse.SUPPRESS, help="also write logs to this file")
    common.add_argument(
        "-i", "--iface", default=argparse.SUPPRESS,
        help="network interface to use (e.g. eth0)",
    )

    parser = argparse.ArgumentParser(
        prog="arpspoofer",
        description="Educational ARP toolkit: spoof, detect, scan, sniff, restore. "
        "Use only on networks you are authorized to test.",
    )
    # Real defaults live on the top-level parser so the attributes always exist.
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    parser.add_argument("--logfile", help="also write logs to this file")
    parser.add_argument("-i", "--iface", help="network interface to use (e.g. eth0)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    p_spoof = sub.add_parser("spoof", parents=[common], help="run a MITM ARP poisoning attack")
    p_spoof.add_argument("-t", "--target", required=True, type=_ip_arg, help="victim IP")
    p_spoof.add_argument("-g", "--gateway", required=True, type=_ip_arg, help="gateway/router IP")
    p_spoof.add_argument("--interval", type=float, default=2, help="seconds between bursts (default 2)")
    p_spoof.add_argument(
        "--no-forward",
        action="store_true",
        help="do NOT auto-enable IP forwarding (this causes a DoS, not a MITM)",
    )

    p_detect = sub.add_parser("detect", parents=[common], help="detect ARP spoofing on the network")
    p_detect.add_argument("--count", type=int, default=0, help="stop after N packets (0 = forever)")

    p_scan = sub.add_parser("scan", parents=[common], help="discover live hosts (IP + MAC)")
    p_scan.add_argument("network", type=_network_arg, help="CIDR to scan, e.g. 192.168.1.0/24")
    p_scan.add_argument("--timeout", type=float, default=2, help="reply timeout in seconds")

    p_sniff = sub.add_parser("sniff", parents=[common], help="sniff plaintext HTTP traffic")
    p_sniff.add_argument("--count", type=int, default=0, help="stop after N packets (0 = forever)")

    p_restore = sub.add_parser("restore", parents=[common], help="manually restore two hosts' ARP tables")
    p_restore.add_argument("-t", "--target", required=True, type=_ip_arg)
    p_restore.add_argument("-g", "--gateway", required=True, type=_ip_arg)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

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
    if args.command == "sniff":
        return sniff.run(iface=args.iface, count=args.count)
    if args.command == "restore":
        spoof.restore(args.target, args.gateway, iface=args.iface)
        spoof.restore(args.gateway, args.target, iface=args.iface)
        return 0
    parser.error("unknown command")


if __name__ == "__main__":
    sys.exit(main())

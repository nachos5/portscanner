import argparse

from .scanner import Scanner
from .utils.types import (
    ip_address_type,
    ip_address_textfile,
    port_range_type,
    port_textfile,
)


def run(args):
    parsed_args = parse_args(args)
    ip_addresses = parsed_args.file if parsed_args.file else parsed_args.list
    ports = (
        parsed_args.portfile
        if parsed_args.portfile
        else list(range(parsed_args.portrange[0], parsed_args.portrange[1] + 1))
    )
    print(ip_addresses)
    # print(ports)
    scanner = Scanner(hostlist=ip_addresses, portlist=ports)
    scanner.scan_all_hosts()


def parse_args(args):
    parser = argparse.ArgumentParser(description="Portscanner")
    ip_group = parser.add_mutually_exclusive_group(required=True)
    ip_group.add_argument(
        "-l", "--list", help="List of IP-addresses", type=ip_address_type, nargs="+",
    )
    ip_group.add_argument(
        "-f",
        "--file",
        help="A textfile with an IP-address in each line",
        type=ip_address_textfile,
    )
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p",
        "--portrange",
        help="The range of ports to scan, defaults to 0-1023 (well-known-ports)",
        type=port_range_type,
        default="0-1023",
    )
    port_group.add_argument(
        "-pf",
        "--portfile",
        help="A textfile containing one port per line",
        type=port_textfile,
    )
    parser.add_argument(
        "-s",
        "--scantype",
        help="Scantype, available choices are FULL, SYN, ACK or XMAS",
        choices=["FULL", "SYN", "ACK", "XMAS"],
        required=True,
    )

    return parser.parse_args(args)

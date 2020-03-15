import argparse
import time

from ipaddress import IPv4Network
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
    # we need to 'extract' all hosts from CIDR network addresses
    temp = []
    for ip in ip_addresses:
        if type(ip) == IPv4Network:
            for i in ip.hosts():
                temp.append(str(i))
        else:
            temp.append(str(ip))
    ip_addresses = temp

    ports = (
        parsed_args.portfile
        if parsed_args.portfile
        else list(range(parsed_args.portrange[0], parsed_args.portrange[1] + 1))
    )

    scan_type = parsed_args.scantype
    randomize = parsed_args.randomize if parsed_args.randomize else ""
    host_discovery = parsed_args.host_discovery
    timeout = parsed_args.timeout
    output_all = parsed_args.output_all
    thread_count = parsed_args.thread_count
    verbose = parsed_args.verbose

    scanner = Scanner(
        hostlist=ip_addresses,
        portlist=ports,
        scan_type=scan_type,
        randomize=randomize,
        host_discovery=host_discovery,
        thread_count=thread_count,
        timeout=timeout,
        output_all=output_all,
        verbose=verbose,
    )

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
    port_group = parser.add_mutually_exclusive_group(required=True)
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
        help="""Scantype, available choices are SOCK, SYN and SYNSTEALTH.
                Defaults to SOCK. Sock utlizes sockets and is much faster
                then SYN and SYNSTEALTH, which utilize Scapy.""",
        choices=["SOCK", "SYN", "SYNSTEALTH"],
        default="SOCK",
    )
    parser.add_argument(
        "-r",
        "--randomize",
        help="Randomizes the order of the portlist/hostlist (or both).",
        choices=["ports", "hosts", "both"],
    )
    parser.add_argument(
        "-hd",
        "--host-discovery",
        help="If this flag is set, each host is pinged before scanning to check status.",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Timeout for each port scan in seconds, defaults to 1 sec.",
        type=float,
        default=1,
    )
    parser.add_argument(
        "-o",
        "--output-all",
        help="""If this flag is set, open, filtered and closed ports
                are outputted, else only open ones.""",
        action="store_true",
    )
    parser.add_argument(
        "-tc",
        "--thread-count",
        help="The maximum amount of threads running at once.",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Set this flag to print additional information to the console while running",
        action="store_true",
    )

    return parser.parse_args(args)

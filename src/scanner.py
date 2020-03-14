import os
import random
import sys
import socket

from datetime import datetime
from ipaddress import IPv4Address
from scapy.all import *
from threading import Thread
from time import sleep

from .utils.thread import ThreadWithCallback
from .utils.types import ip_address_type


class Scanner:
    """
    Class for port scanning.

    Arguments:
    hostlist - list of hosts to scan.
    portlist - list of ports to scan for each host.
    thread_count - the maximum number of threads running at once. Defaults to 100.
    timeout - timeout in seconds for each scan.
    scan_type - type of scan to use. Choices are SYN or SYNSTEALTH. Defaults to SYNSTEALTH.
    randomize - wether to randomize lists or not. Choices are ports, hosts and both.
                Defaults to no randomization.
    host_discovery - whether to ping host before scanning or not to check status.
    output_all - whether to output open, filtered and closed ports or only open ones.
    verbose - additional information is printed to the console.
    """

    def __init__(self, *args, **kwargs):
        self.hostlist = kwargs.pop("hostlist") if "hostlist" in kwargs else []
        self.portlist = sorted(kwargs.pop("portlist")) if "portlist" in kwargs else []
        self.portlist_len = len(self.portlist)
        self.thread_count = (
            int(kwargs.pop("thread_count")) if "thread_count" in kwargs else 100
        )
        self.timeout = kwargs.pop("timeout") if "timeout" in kwargs else 1

        scan_type_choices = ["SYN", "SYNSTEALTH"]
        scan_type = kwargs.pop("scan_type") if "scan_type" in kwargs else "SYNSTEALTH"
        if scan_type not in scan_type_choices:
            raise Exception(
                f"Invalid scan type. Available choices are {' '.join(scan_type_choices)}."
            )
        self.scan_type = scan_type
        randomize_choices = ["", "ports", "hosts", "both"]
        randomize = kwargs.pop("randomize") if "randomize" in kwargs else ""
        if randomize not in randomize_choices:
            raise Exception(
                f"Invalid randomize parameter. Available choices are {' '.join(randomize_choices)}."
            )
        if randomize == "hosts":
            random.shuffle(self.hostlist)
        elif randomize == "ports":
            random.shuffle(self.portlist)
        elif randomize == "both":
            random.shuffle(self.hostlist)
            random.shuffle(self.portlist)

        self.output_all = kwargs.pop("output_all") if "output_all" in kwargs else False
        self.host_discovery = (
            kwargs.pop("host_discovery") if "host_discovery" in kwargs else False
        )

        # utility variables
        self.verbose = kwargs.pop("verbose") if "verbose" in kwargs else False
        self.SYNACK = 0x12
        self.RSTACK = 0x14
        self.ICMP_prohibited_codes = [1, 2, 3, 9, 10, 13]
        self.init_port_dict()
        self.init_well_known()

    def init_port_dict(self):
        self.port_dict = dict(open=[], closed=[], filtered=[])

    def init_well_known(self):
        self.well_known = dict()
        filepath = os.path.join(os.path.dirname(__file__), "well_known.txt")
        try:
            with open(filepath, "r") as well_known_txt:
                for line in well_known_txt.readlines():
                    port, info = line.strip().split(":")
                    self.well_known[int(port)] = info
        except Exception as e:
            print(e)

    def print_port_dict(self):
        c = ", ".join(
            [
                f"{x}-{self.well_known[x]}" if x in self.well_known else str(x)
                for x in sorted(self.port_dict["closed"])
            ]
        )
        o = ", ".join(
            [
                f"{x}-{self.well_known[x]}" if x in self.well_known else str(x)
                for x in sorted(self.port_dict["open"])
            ]
        )
        f = ", ".join(
            [
                f"{x}-{self.well_known[x]}" if x in self.well_known else str(x)
                for x in sorted(self.port_dict["filtered"])
            ]
        )
        if o:
            print(f"Open ports:\n{o}\n")
        else:
            print("No open ports detected.")
        if self.output_all:
            if c:
                print(f"Closed ports:\n{c}\n")
            else:
                print("No closed ports detected.")
            if f:
                print(f"Filtered ports:\n{f}\n")
            else:
                print("No filtered ports detected.")

    def add_host(self, host):
        self.hostlist.append(host)

    def add_port(self, port):
        self.portlist.append(port)
        self.portlist_len += 1

    def randomize_hostlist(self):
        random.shuffle(self.hostlist)

    def randomize_postlist(self):
        random.shuffle(self.portlist)

    def random_ip_address(self):
        return str(IPv4Address(random.getrandbits(32)))

    def random_port(self):
        return int(RandShort())

    def checkhost(self, host):
        try:
            sr1(IP(dst=host) / ICMP(), verbose=False)
            return True
        except KeyboardInterrupt:
            print("Program interrupted... Exiting...")
            os._exit(1)
        except Exception:
            print("Couldn't Resolve Target")
            return False

    def get_packets(self, host, port, flags="S"):
        # generating IP packet
        IP_Packet = IP()
        IP_Packet.dst = host
        # generating TCP packet
        TCP_Packet = TCP()
        TCP_Packet.sport = self.random_port()
        TCP_Packet.dport = port
        TCP_Packet.flags = flags
        return (IP_Packet, TCP_Packet)

    def get_response_packet(self, IP_Packet, TCP_Packet):
        return sr1(IP_Packet / TCP_Packet, timeout=self.timeout, verbose=False)

    def portscan(self, host, port):
        if self.scan_type == "SYNSTEALTH":
            return self.syn_scan(host, port)
        elif self.scan_type == "SYN":
            return self.syn_scan(host, port, stealth=False)

    def syn_scan(self, host, port, stealth=True):
        try:
            IP_Packet, TCP_Packet = self.get_packets(host, port)
            # generating final packet
            res_packet = self.get_response_packet(IP_Packet, TCP_Packet)
            if res_packet:
                if res_packet.haslayer(TCP):
                    res_flags = res_packet.getlayer(TCP).flags
                    if res_flags == self.SYNACK:
                        self.port_dict["open"].append(port)
                        if self.verbose:
                            print(f"Port {port} is open")
                    elif res_flags == self.RSTACK:
                        self.port_dict["closed"].append(port)
                        if self.verbose:
                            print(f"Port {port} is closed")
                elif res_packet.haslayer(ICMP):
                    if (
                        int(res_packet.getlayer(ICMP).type) == 3
                        and int(res_packet.getlayer(ICMP).code)
                        in self.ICMP_prohibited_codes
                    ):
                        self.port_dict["filtered"].append(port)
                        if self.verbose:
                            print(f"Port {port} is filtered")
            else:
                self.port_dict["closed"].append(port)
                if self.verbose:
                    print(f"Port {port} is closed")

            if stealth:
                # we send a rst packet to terminate the connection (stealth scan)
                TCP_Packet.flags = "R"
                send(IP_Packet / TCP_Packet, verbose=False)
        except KeyboardInterrupt:
            if stealth:
                # we send a rst packet to terminate the connection (stealth scan)
                TCP_Packet.flags = "R"
                send(IP_Packet / TCP_Packet, verbose=False)

    def scan_host(self, host, counter=0):
        """
        This function scans every port in the portlist for this particular host.
        A new thread is generated for every port which calls the portscan function.
        Threads are created and run in batches, the last thread in every batch is
        responsible for calling the next batch using a callback function.
        """
        try:
            if counter == 0:
                if self.host_discovery:
                    is_up = self.checkhost(host)
                    if not is_up:
                        return
            batch_start = counter
            batch_end = counter + self.thread_count - 1
            threads = [
                Thread(target=self.portscan, kwargs={"host": host, "port": port})
                for port in self.portlist[batch_start:batch_end]
            ]
            if batch_end < self.portlist_len:
                # last thread in this batch, a callback is used to run the next one.
                threads.append(
                    ThreadWithCallback(
                        target=self.portscan,
                        kwargs={"host": host, "port": self.portlist[batch_end],},
                        callback=self.scan_host_callback,
                        callback_kwargs={"host": host, "counter": batch_end + 1,},
                    )
                )
            # start threads
            [thread.start() for thread in threads]
            [thread.join() for thread in threads]
        except KeyboardInterrupt:
            print("Program interrupted... Exiting...")
            os._exit(1)

    def scan_host_callback(self, *args, **kwargs):
        """
        A callback used for the last thread of each scanning batch,
        is responsible for running the next batch.
        """
        host = kwargs.pop("host")
        counter = kwargs.pop("counter")
        self.scan_host(host, counter)

    def scan_all_hosts(self):
        """
        Iterates through the hostlist and scans all ports in the portlist.
        """
        try:
            t1 = datetime.now()
            for host in self.hostlist:
                print(f"Scanning host: {host}")
                self.scan_host(host)
                self.print_port_dict()
                self.init_port_dict()
                print()
            print(f"Total time: {datetime.now() - t1}")
        except KeyboardInterrupt:
            print("Program interrupted... Exiting...")
            os._exit(1)


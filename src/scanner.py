import os
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
    Class for port scanning. This class must be initialized with no arguments,
    where class variables can be modified dynamically or the classes functions
    can be used as utility functions. Or it can be initialized with all of the
    following arguments:

    hostlist - list of hosts to scan.
    portlist - list of ports to scan for each host.
    thread_count - the maximum number of threads running at once.
    timeout - timeout in seconds for each scan.

    scan_type - *optional - type of scan to use. Choices are... Defaults to SYN.
    """

    def __init__(self, *args, **kwargs):
        kwargs_bool = bool(kwargs)
        self.hostlist = kwargs.pop("hostlist") if kwargs_bool else []
        self.portlist = sorted(kwargs.pop("portlist")) if kwargs_bool else []
        self.portlist_len = len(self.portlist) if kwargs_bool else 0
        self.thread_count = int(kwargs.pop("thread_count")) if kwargs_bool else 100
        self.timeout = kwargs.pop("timeout") if kwargs_bool else 1

        scan_type_choices = ["SYN", "XMAS"]
        scan_type = kwargs.pop("scan_type") if "scan_type" in kwargs else "SYN"
        if scan_type not in scan_type_choices:
            raise Exception(
                f"Invalid scan type. Available choices are {' '.join(scan_type_choices)}."
            )
        self.scan_type = scan_type

        # utility variables
        self.debug = False if kwargs_bool else True
        self.SYNACK = 0x12
        self.RSTACK = 0x14
        self.init_port_dict()

    def init_port_dict(self):
        self.port_dict = dict(open=[], closed=[], filtered=[])

    def print_port_dict(self):
        o = ", ".join(sorted([str(x) for x in self.port_dict["open"]]))
        c = ", ".join(sorted([str(x) for x in self.port_dict["closed"]]))
        f = ", ".join(sorted([str(x) for x in self.port_dict["filtered"]]))
        if o:
            print(f"Open ports:\n{o}\n")
        else:
            print("No open ports.")
        if c:
            print(f"Closed ports:\n{c}\n")
        else:
            print("No closed ports.")
        if f:
            print(f"Filtered ports:\n{f}\n")
        else:
            print("No filtered ports.")

    def add_host(self, host):
        pass

    def add_port(self, port):
        pass

    def random_ip_address(self):
        return str(IPv4Address(random.getrandbits(32)))

    def random_port(self):
        return int(RandShort())

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

    def portscan(self, host, port):
        if self.scan_type == "SYN":
            return self.syn_scan(host, port)

    def syn_scan(self, host, port):
        try:
            IP_Packet, TCP_Packet = self.get_packets(host, port)
            # generating final packet
            res_packet = sr1(
                IP_Packet / TCP_Packet, timeout=self.timeout, verbose=False
            )
            if res_packet:
                res_flags = res_packet.getlayer(TCP).flags
                if res_flags == self.SYNACK:
                    self.port_dict["open"].append(port)
                    if self.debug:
                        print(f"Port {port} is open")
                elif res_flags == self.RSTACK:
                    self.port_dict["closed"].append(port)
                    if self.debug:
                        print(f"Port {port} is closed")
            # we send a rst packet to terminate the connection (stealth scan)
            TCP_Packet.flags = "R"
            send(IP_Packet / TCP_Packet, verbose=False)
        except KeyboardInterrupt:
            # we send a rst packet to terminate the connection (stealth scan)
            TCP_Packet.flags = "R"
            send(IP_Packet / TCP_Packet, verbose=False)

    def xmas_scan(self, host, port):
        pass

    def scan_host(self, host, counter=0):
        """
        This function scans every port in the portlist for this particular host.
        A new thread is generated for every port which calls the portscan function.
        Threads are created and run in batches, the last thread in every batch is
        responsible for calling the next batch using a callback function.
        """
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
        t1 = datetime.now()
        for host in self.hostlist:
            print(f"Scanning host: {host}")
            self.scan_host(host)
            self.print_port_dict()
            self.init_port_dict()
            print()
        print(f"Total time: {datetime.now() - t1}")


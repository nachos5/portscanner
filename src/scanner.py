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
    use_timeout - whether a timeout should be used for each scan or not.
    """

    def __init__(self, *args, **kwargs):
        self.hostlist = kwargs.pop("hostlist") if kwargs else []
        self.portlist = sorted(kwargs.pop("portlist")) if kwargs else []
        self.portlist_len = len(self.portlist) if kwargs else 0
        self.thread_count = int(kwargs.pop("thread_count")) if kwargs else 100
        self.use_timeout = kwargs.pop("use_timeout") if kwargs else False
        # optional argument - some users might experience errors without declaring an interface
        if "interface" in kwargs:
            self.interface = kwargs.pop("interface")
        else:
            self.interface = None

    def add_host(host):
        pass

    def add_port(port):
        pass

    def random_ip_address(self):
        return str(IPv4Address(random.getrandbits(32)))

    def random_port(self):
        return random.randint(0, 65535)

    # def portscan(self, hostname, port):
    #     """
    #     Scans a single port for a particular host. If use_timeout is set, a 1 sec.
    #     timeout is used for the scan.
    #     """
    #     serverIP = socket.gethostbyname(hostname)
    #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     if self.use_timeout:
    #         sock.settimeout(1)

    #     try:
    #         c = sock.connect((serverIP, port))
    #         print(f"Port {port} is open")
    #         c.close()
    #     except:
    #         pass

    def portscan(self, host, port):
        # generating IP packet
        IP_Packet = IP()
        IP_Packet.dst = host
        # generating TCP packet
        TCP_Packet = TCP()
        TCP_Packet.sport = self.random_port()
        TCP_Packet.dport = port
        TCP_Packet.flags = "S"
        # generating final packet
        final_packet = IP_Packet / TCP_Packet
        # send and receive
        if self.interface:
            res_packet = sr1(
                final_packet, timeout=1, verbose=False, iface=self.interface
            )
            print(res_packet)
        else:
            res_packet = sr1(final_packet, timeout=1, verbose=False)
        if res_packet:
            print("wtf")
            print(res_packet)
            # res_flags = res_packet.getlayer(TCP).flags
            # if res_flags == SYNACK:
            #     print(f"Port {port} is open")

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
            print()
        print(f"time: {datetime.now() - t1}")


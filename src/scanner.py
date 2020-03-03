import os
import sys
import socket

from datetime import datetime
from threading import Thread


class Scanner:
    def __init__(self, *args, **kwargs):
        self.hostlist = kwargs.pop("hostlist")
        self.portlist = sorted(kwargs.pop("portlist"))

    def portscan(self, hostname, port):
        serverIP = socket.gethostbyname(hostname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        try:
            c = sock.connect((serverIP, port))
            print(f"Port {port} is open")
            c.close()
        except:
            pass

    def scan_host(self, hostname):
        print(f"Scanning host: {hostname}")
        t1 = datetime.now()
        for port in self.portlist:
            thread = Thread(
                target=self.portscan, kwargs={"hostname": hostname, "port": port}
            )
            thread.start()
        print(f"time: {datetime.now() - t1}")

    def scan_all_hosts(self):
        for host in self.hostlist:
            self.scan_host(host)


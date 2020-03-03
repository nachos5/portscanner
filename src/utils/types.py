from argparse import ArgumentTypeError

from ipaddress import ip_address, ip_network
from validators import domain


def ip_address_type(address):
    try:
        if ip_address(address):
            return ip_address(address)
    except:
        try:
            if ip_network(address):
                return ip_network(address)
        except:
            try:
                if domain(address):
                    return address
            except:
                raise ArgumentTypeError(
                    f"{address} is not a valid IP-address or hostname"
                )


def ip_address_textfile(filepath):
    ips = []
    with open(filepath, "r") as textfile:
        for line in textfile.readlines():
            try:
                ips.append(ip_address_type(line.strip()))
            except:
                raise ArgumentTypeError(f"{line.strip()} is not a valid IP-address")

    return ips


def port_range_type(range_string):
    error_message = "Please use the format 'low-high' where low and high are both integers and low < high"
    split = range_string.split("-")
    if len(split) == 2:
        try:
            low = int(split[0])
            high = int(split[1])
            if low > high:
                raise ArgumentTypeError(error_message)
            return (low, high)
        except:
            raise ArgumentTypeError(error_message)
    else:
        raise ArgumentTypeError(error_message)


def port_textfile(filepath):
    ports = []
    out_of_range_port = None
    with open(filepath, "r") as textfile:
        for line in textfile.readlines():
            try:
                port = int(line.strip())
                if port >= 0 and port <= 65535:
                    ports.append(port)
                else:
                    out_of_range_port = port
                    break
            except:
                raise ArgumentTypeError(f"{line.strip()} is not an integer")
    if out_of_range_port:
        raise ArgumentTypeError(f"port value {out_of_range_port} is out of range")

    return ports

# Port Scanner

Made by:

* Guðmundur Óli Norland (gon2@hi.is)
* Hjalti Geir Garðarsson (hgg29@hi.is)

This is a TCP port scanner made with Python 3. Install required packages by running:

    pip install -r requirements.txt

We recommend installing in a isolated virtual environment which you can setup by running (here using the name env):

    python -m venv env

## Usage

portscanner.py [-h] (-l LIST [LIST ...] | -f FILE)
                      (-p PORTRANGE | -pf PORTFILE) [-s {SYNSTEALTH,SYN}]
                      [-r {ports,hosts,both}] [-hd] [-t TIMEOUT] [-o]
                      [-tc THREAD_COUNT] [-v]

Arguments:

* -h, --help
  * show this help message and exit

* -l LIST [LIST ...], --list LIST [LIST ...]
  * List of IP-addresses

* -f FILE, --file FILE
  * A textfile with an IP-address in each line

* -p PORTRANGE, --portrange PORTRANGE
  * The range of ports to scan, defaults to 0-1023 (well-known-ports)

* -pf PORTFILE, --portfile PORTFILE
  * A textfile containing one port per line

* -s {SOCK,SYN,SYNSTEALTH}, --scantype {SOCK,SYN,SYNSTEALTH}
  * Scantype, available choices are SOCK, SYN and SYNSTEALTH. Defaults to SOCK. Sock utlizes sockets and is much faster then SYN and SYNSTEALTH, which utilize Scapy.

* -r {ports,hosts,both}, --randomize {ports,hosts,both}
  * Randomizes the order of the portlist/hostlist (or both).

* -hd, --host-discovery
  * If this flag is set, each host is pinged before scanning to check status.

* -t TIMEOUT, --timeout TIMEOUT
  * Timeout for each port scan in seconds, defaults to 1 sec.

* -o, --output-all
  * If this flag is set, open, filtered and closed ports are outputted, else only open ones.

* -tc THREAD_COUNT, --thread-count THREAD_COUNT
  * The maximum amount of threads running at once.

* -v, --verbose
  * Set this flag to print additional information to the console while running

## Examples

Scanning a range of ports of one host:

    python portscanner.py -l scanme.nmap.org -p 1-100

Scanning a range of ports of one host using SYN stealth scan (Scapy):

    python portscanner.py -l scanme.nmap.org -p 1-100 -s SYNSTEALTH -t 2

Scanning ports declared in a text file for multiple hosts:

    python portscanner.py -l scanme.nmap.org 10.0.20.0/30 -pf ./tests/ports.txt

Scanning a range of ports for hosts declared in a text file. Additionally, maximum number of threads and timeout is declared.

    python portscanner.py -f ./tests/ips.txt -p 1-60000 -tc 10000 -t 0.5

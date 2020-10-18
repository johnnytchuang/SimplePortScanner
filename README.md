# SimplePortScanner
SimplePortScanner is a port scanning tool as the name suggested. It uses both __TCP__ and __UDP__ connections to destect port status.

## Dependencies
This program uses `netaddr`, `scapy`, `numpy`, `tabulate`, `html-creator` for some of the features.
Use `pip install netaddr scapy numpy tabulate html-creator` to install these dependencies.

## Usage

**NOTE:** Use `python .\scan.py -h` to display commandline options.

Usage 1: 
Scanning hosts and ports from files and output to both text and html files name **report __(excluding extension)__**.
```python .\scan.py --host-file hosts.txt --port-file ports.txt --file report --text --html```

Usage 2:
Scanning only one host and a range of ports specified using commandline and output to a text file name **report __(excluding extension)__**.
```python .\scan.py --host 192.168.86.42 --port 20-30 --file oreportut```

Usage 3:
Scanning multiple hosts and multiple ranges of ports specified using commandline and output to commandline.
```python .\scan.py --host 192.168.86.42 192.168.86.255  --port 20-30 70-90```

Usage 4:
Scanning only one host (from commandline) and a range of ports (from a file) and output to a html file name **report __(excluding extension)__**.
Set the UDP timeout to 1 second and the __wait-time to check host online status__ to 1 second.
```python .\scan.py --host 192.168.86.42 --port-file ports.txt --file out --html --udp-timeout 1 --test-host-timeout 1```



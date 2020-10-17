import os, sys, argparse, time, netaddr
from scapy.all import *
import numpy as np

class Result:
    def __init__(self, host, port, protocol, status):
        self.__dict__.update(locals())
    def __str__(self):
       return "{}\t{}\t{}".format(self.port, self.protocol, self.status)
    def __repr__(self):
        return "{}\t{}\t{}".format(self.port, self.protocol, self.status)
    def __err__(self):
        return str(self.__dict__)
    def __eq__(self, other):
        return (self.host == other.host) and (self.port == other.port) and (self.protocol == other.protocol) and (self.status == other.status)

    def __lt__(self, other):
        if self == other:
            raise Exception("Equal Result information: \n{}\n{}".format(self.__err__(),other.__err__()))

        if self.host != other.host:
            s = np.array(self.host.split('.')).astype(int)
            o = np.array(other.host.split('.')).astype(int)
            i = np.argwhere(s != o).flatten()[0]
            return (s < o)[i]
        elif self.port != other.port:
            return self.port < other.port
        elif self.protocol != other.protocol:
            return ord(self.protocol[0]) < ord(other.protocol[0])
        elif self.status != other.status:
            return len(self.status) < len(other.status)
        else:
            raise Exception("Identical Result information: \n{}\n{}".format(self.__err__(),other.__err__()))

def build_packet(host,port,protocol,flag='S'):
    if protocol.lower() == 'tcp':
        return IP(dst=host)/TCP(dport=port,flags=flag)
    elif protocol.lower() == 'udp':
        return IP(dst=host)/UDP(dport=port)
    else:
        raise Exception('Invalid network protocol:', protocol)

def tcp_normal(hosts, ports):
    results = []
    open_count = 0
    for host in hosts:
        o = 0
        for port in ports:
            print('Scanning port {} on {}...'.format(port, host), end='\r', flush=True)
            packet = build_packet(host, port,'tcp','S')
            response = sr1(packet, timeout=0.5, verbose=0)
            if type(response) != type(None) and response.getlayer(TCP).flags == 0x12:
                results.append(Result(host,port,'TCP','Open'))
                o += 1
            sr(IP(dst=host)/TCP(dport=response.sport, flags='R'), timeout=0.5,verbose=0)
        print('Scanned {} ports over TCP on {}, {} open port(s)'.format(len(ports),host,o))
        open_count += o
    return results

def udp(hosts,ports,timeout=0.5):
    results = []
    for host in hosts:
        for port in ports:
            packet = build_packet(host,port,'udp')
            response = sr1(packet,timeout=timeout,verbose=0)
            if type(response) == type(None):
                results.append(Result(host, port, 'UDP',"Open|Filtered"))
            elif response.haslayer(UDP):
                results.append(Result(host, port, 'UDP',"Open"))
            elif(response.haslayer(ICMP)):
                if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,9,10,13]:
                    results.append(Result(host, port, 'UDP',"Filtered"))
            else:
                print("CHECK",port,host,'UDP')
    return results

def get_args():
    parser = argparse.ArgumentParser(description='Port scanning over both TCP and UDP connections')
    hopt = parser.add_mutually_exclusive_group(required=True)
    hopt.add_argument('--host', metavar='HOST', type=str, nargs='+',
                    help='Commandline input for one or moe hosts.')
    hopt.add_argument('--host-file', metavar='HOST', type=str, nargs=1,
                    help='A file containing the hosts.')

    popt = parser.add_mutually_exclusive_group(required=True)
    popt.add_argument('--port', metavar='PORT', type=int, nargs='+',
                    help='Commandline input for one or moe hosts.')
    popt.add_argument('--port-file', metavar='PORT', type=str, nargs=1,
                    help='A file containing the ports.')
    
    return parser.parse_args()

def parse(args):
    hosts = []
    ports = []

    if args.host != None:
        for ip in args.host:
            hosts += [ str(_ip) for _ip in netaddr.IPNetwork(ip) ]
    elif args.host_file != None:
        with open(args.host_file, 'r') as f:
            for line in f:
                hosts.append(line.lstrip().rstrip())

    if args.port != None:
        ports = args.ports
    elif args.port_file != None:
        with open(args.port_file, 'r') as f:
            for line in f:
                ports.append(line.lstrip().rstrip())

    return hosts, ports

def main(args):
    hosts, ports = parse(args)

    s = time.time()

    results = tcp_normal(hosts, ports)
    results += udp(hosts, ports)
    print(sorted(results))
    print('Completed in {} seconds'.format(time.time() - s))


if __name__ == "__main__":
    args = get_args()
    print(args)
    #main(args)


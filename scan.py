import os, sys, argparse, time, netaddr
from scapy.all import *
import numpy as np
from tabulate import tabulate
from html_creator import *

# result class to consolidate data structure
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

# construct packets
def build_packet(host,port,protocol,flag='S'):
    if protocol.lower() == 'tcp':
        return IP(dst=host)/TCP(dport=port,flags=flag)
    elif protocol.lower() == 'udp':
        return IP(dst=host)/UDP(dport=port)
    elif protocol.lower() == 'icmp':
        return IP(dst=host)/ICMP()
    else:
        raise Exception('Invalid network protocol:', protocol)

# check to see if the host is up and running using ICMP
def check_host(host,timeout):
    print('Checking if {} is up... '.format(host), end='', flush=True)
    packet = build_packet(host,0,'icmp')
    response = sr1(packet, timeout=timeout, verbose=0)  # send the packet
    # if we get a response, that means the host is up
    if response == None:
        print(host,"is not up.")
        return False
    print(host,"is up.")
    return True

# sends packets over TCP
def tcp_normal(host, ports):
    results = []
    open_count = 0
    for port in ports:
        print('\rTCP Connection scanning port {} on {}... '.format(port, host), end='', flush=True)
        packet = build_packet(host, port,'tcp','S') # normal connection handshake
        response = sr1(packet, timeout=0.5, verbose=0)  # end the packet
        # 0x12 is the flag for SYN-ACK
        if (response != None) and (response.getlayer(TCP) != None) and (response.getlayer(TCP).flags == 0x12):
            results.append(Result(host,port,'TCP','Open'))
            open_count += 1
        sr(IP(dst=host)/TCP(dport=port, flags='R'), timeout=0.5,verbose=0)  # terminate the connection
    print('Scanned {} ports over TCP on {}, {} open port(s)'.format(len(ports),host,open_count))

    return results

# sends packets over UDP
def udp(host,ports,timeout):
    results = []
    count = { 'open': 0, 
             'filtered': 0, 
             'maybe': 0 }
    for port in ports:
        print('\rUDP Connection scanning port {} on {}... '.format(port, host), end='', flush=True)
        packet = build_packet(host,port,'udp')
        response = sr1(packet,timeout=timeout,verbose=0)    # send the packet
        # we can't be sure if nothing comes back
        if response == None:
            results.append(Result(host, port, 'UDP',"Open|Filtered"))
            count['maybe'] += 1
        # it's open if we get a response
        elif response.haslayer(UDP):
            results.append(Result(host, port, 'UDP',"Open"))
            count['open'] += 1
        # it's closed if the reponse has ICMP error type 3, but we don't record it
        # it's filtered if the reponse has ICMP error type 1,2,9,10,13
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,9,10,13]:
                results.append(Result(host, port, 'UDP',"Filtered"))
                count['filtered'] += 1
        else:
            print("CHECK",port,host,'UDP')
    print('Scanned {} ports over UDP on {}, {} open port(s), {} filtered port(s), {} port(s) didn\'t respond.'.format(len(ports),host,count['open'],count['filtered'],count['maybe']))
    return results

def get_args():
    parser = argparse.ArgumentParser(description='Port scanning over both TCP and UDP connections')
    # choose between --host and --host-file
    hopt = parser.add_mutually_exclusive_group(required=True)
    hopt.add_argument('--host', metavar='HOST', type=str, nargs='+',
                    help='Commandline input for one or moe hosts.')
    hopt.add_argument('--host-file', metavar='HOST', type=str, nargs=1,
                    help='A file containing the hosts.')
    # choose between --port and --port-file
    popt = parser.add_mutually_exclusive_group(required=True)
    popt.add_argument('--port', metavar='PORT', type=str, nargs='+',
                    help='Commandline input for one or moe hosts.')
    popt.add_argument('--port-file', metavar='PORT', type=str, nargs=1,
                    help='A file containing the ports.')
    # output format options
    parser.add_argument('--file', metavar='FILE_NAME', type=str, nargs=1,
                    help='Output file name')
    parser.add_argument('--text', dest='to_text', action='store_true', default=False)
    parser.add_argument('--html', dest='to_html', action='store_true', default=False)
    # other options such as udp timeout and check_host() wait time
    parser.add_argument('--udp-timeout', metavar='UDP_TIMEOUT', type=str, nargs=1, default='0.5',
                    help='Timeout variable for UDP.')
    parser.add_argument('--test-host-timeout', metavar='HOST_TIMEOUT', type=str, nargs=1, default='10',
                    help='Wait time for checking if each host is online.')
    
    return parser.parse_args()

def parse(args):
    hosts = []
    ports = []

    # get a list of hosts
    if args.host != None:
        for ip in args.host:
            # get specific range of ip addresses from subnet masks
            hosts += [ str(_ip) for _ip in netaddr.IPNetwork(ip) ]
    elif args.host_file != None:
        with open(args.host_file[0], 'r') as f:
            for line in f:
                # get specific range of hosts from subnet masks
                # a line might be something like 192.168.1.0/24
                hosts += [ str(ip) for ip in netaddr.IPNetwork(line.lstrip().rstrip()) ]

    # get a list of ports
    if args.port != None:
        for p in args.port:
            # convert string to int
            port_range = np.array(p.split('-')).astype(int)
            if len(port_range) == 1:
                ports.append(port_range[0])
            # get a specific range of ports from the format NUM1-NUM2
            #  Ex. --port 22-80  --> port range 22 to 80 inclusive
            elif len(port_range) == 2:
                ports += [_p for _p in range(port_range[0], port_range[1]+1)]
            else:
                raise Exception("Error reaing port: {}".format(args.port))
    elif args.port_file != None:
        with open(args.port_file[0], 'r') as f:
            for num, line in enumerate(f):
                # convert string to int
                port_range = np.array(line.lstrip().rstrip().split('-')).astype(int)
                if len(port_range) == 1:
                    ports.append(port_range[0])
                elif len(port_range) == 2:
                    # get a specific range of ports from the format NUM1-NUM2
                    #  Ex. --port 22-80  --> port range 22 to 80 inclusive
                    ports += [_p for _p in range(port_range[0], port_range[1]+1)]
                else:
                    raise Exception("Error reaing port file: Line {}\n{}".format(num, line.rstrip()))

    # parse output format options
    output_options = {}
    if args.file != None:
        fname = args.file[0]
        output_options[fname] = {'text':args.to_text, 'html':args.to_html}
        if (not args.to_html) and (not args.to_text):
            output_options[fname]['text'] = True

    return set(hosts), set(ports), float(args.udp_timeout[0]), float(args.test_host_timeout[0]), output_options

def print_result(results, output_options):
    # sort result for readability
    results = sorted(results)

    # initiate tabulate table with headers
    detailed_table = [['Host','Port','Protocol','Status']]
    status_table = [['Status', 'Protocol', "Number of Ports"]]

    host_cache = ""
    host_count = 0
    port_count = len(results)
    status_stats = {}   # store port statistics { status : { protocol : count } }
    for result in results:
        # avoid printing duplicated host/IP 
        # host is empty is it's the same as last row
        host = ''
        if result.host != host_cache:
            host = result.host
            host_cache = result.host
            host_count += 1

        # adding numbers to port statistics
        try:
            status_stats[result.status][result.protocol] += 1
        except KeyError:
            try:
                status_stats[result.status][result.protocol] = 1
            except KeyError:
                status_stats[result.status] = { result.protocol: 1 }

        # add a row to the detailed tabular table
        detailed_table.append([host, result.port, result.protocol, result.status])

    # convert the statistics table to tabular table
    for ssk, ssv in status_stats.items():
        for sk, sv in ssv.items():
            status_table += [[ ssk, sk, sv ]]

    # commandline output
    if len(output_options) == 0:
        print('Report Summary')
        print('Number of Unique Hosts Scanned: {}'.format(host_count))
        print('Number of Ports Responded: {}'.format(port_count))
        print('\nPort Status Statistics')
        print(tabulate(status_table, headers='firstrow'))
        print('\n\nDetailed Report')
        print(tabulate(detailed_table, headers="firstrow"))
        print()
    else:   # text and/or html output
        for fname, formats in output_options.items():
            for fmt, do in formats.items(): # do it boolean indicating whether to generate the specific format or not
                if do:
                    ext = '.txt' if fmt == 'text' else '.html'
                    # generate html
                    if fmt == 'html':
                        doc = Document(title='Port Scan Report')
                        doc.body.append(Element(tag='h1',content='Report Summary'))
                        doc.body.append(Element(tag='p',content='Number of Unique Hosts Scanned: {}'.format(host_count)))
                        doc.body.append(Element(tag='p',content='Number of Ports Responded: {}'.format(port_count)))
                        doc.body.append(Element(tag='h2',content='Port Status Statistics'))
                        doc.body.append(Element(tag='p',content=tabulate(status_table, headers='firstrow',tablefmt='html')))
                        doc.body.append(Element(tag='h1',content='Detailed Report'))
                        doc.body.append(Element(tag='p',content=tabulate(detailed_table, headers="firstrow", tablefmt='html')))
                        with open(fname+ext,'w+') as out:
                            out.write(str(doc)+'\n')
                    # generate text file
                    if fmt == 'text':   
                        with open(fname+ext, 'w+') as out:
                            out.write('Report Summary\n')
                            out.write('Number of Unique Hosts Scanned: {}\n'.format(host_count))
                            out.write('Number of Ports Responded: {}\n'.format(port_count))
                            out.write('\nPort Status Statistics\n')
                            out.write(tabulate(status_table, headers='firstrow'))
                            out.write('\n\nDetailed Report\n')
                            out.write(tabulate(detailed_table, headers="firstrow"))
                            out.write('\n')

def main(args):
    # Parse commandline arguments
    hosts, ports, udp_timeout, check_status_timeout, out_opt = parse(args)

    # record start time
    s = time.time()

    # run scanning and store result
    results = []
    for host in hosts:
        if check_host(host,check_status_timeout):
            results += tcp_normal(host, ports)
            results += udp(host, ports, udp_timeout)
        print()
    
    # print result depending on the output format
    print_result(results, out_opt)

    print('Completed scanning in {} seconds'.format(round(time.time() - s,2)))


if __name__ == "__main__":
    args = get_args()
    main(args)


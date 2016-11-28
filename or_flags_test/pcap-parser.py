__author__ = 'Roee'

import csv
import dpkt
import argparse
from time import clock
from dnslib import *


def _packets(filename, ip_filter=None):
    with open(filename, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type == 2048:
                    ## IP Packet
                    ip = eth.data
                    ip_src = socket.inet_ntoa(ip.src)
                    ip_dst = socket.inet_ntoa(ip.dst)
                    if ip.p == 17:
                        ## UDP
                        udp = ip.data
                        if udp.dport == 53 and (ip_filter is None or ip_dst == ip_filter) and len(udp.data) > 0:
                            ## DNS request
                            dns = DNSRecord.parse(udp.data)
                            yield (dns, ip_src, ip_dst)
            except Exception, e:
                print e
                pass


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Input pcap filename')
    parser.add_argument('output', help='Output filename')
    parser.add_argument('-prefix', help='prefix to .research.lab.sit.cased.de', default='1')
    parser.add_argument('-ip', help='IP address of name server')

    args = parser.parse_args()

    domain = args.prefix + ".research.lab.sit.cased.de"
    domain_len = len(domain)+1

    start = clock()
    with open(args.output, "wb") as resultsFile:
        writer = csv.writer(resultsFile)
        writer.writerow(["destip", "rd", "ra"])

        count = 0
        for (dns, ip_src, ip_dst) in _packets(args.input, args.ip):
            if dns.questions and domain in str(dns.questions[0].qname):
                destip = str(dns.questions[0].qname)[:-domain_len]
                writer.writerow([destip, dns.header.rd, dns.header.ra])

                count += 1
                if count % 100000 == 0:
                    print clock()-start

        print "count=", count

if __name__ == "__main__":
    main()

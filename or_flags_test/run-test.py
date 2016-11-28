__author__ = 'Roee'

import csv
import dns.rcode
from resolvers_scanner import ResolversScanner
from dns_facilities import DnsFacilities


class Main:
    def __init__(self, output_filename, domain, resolvers_list, recursion_desired,  max_pending=600, request_timeout=10):
        self.outputFilename = output_filename

        self.domain = domain
        self.resolvers_list = resolvers_list
        self.recursion_desired = recursion_desired
        self.max_pending = max_pending
        self.request_timeout = request_timeout

    def run(self):
        with open(self.outputFilename, 'wb') as resultsFile:
            writer = csv.writer(resultsFile)

            writer.writerow(["destip", "port", "rcode", "flags", "answers", "elapsed"])

            def generate_query(item):
                domain_to_query = DnsFacilities.generate_domain_to_query(self.domain, item)
                query = DnsFacilities.build_query(domain_to_query, self.recursion_desired)
                dest = item
                return query, dest

            def response_received(result):
                response, address, time_elapsed = result

                if response is not None:
                    writer.writerow([address[0],
                                     address[1],
                                     dns.rcode.to_text(response.rcode()),
                                     dns.flags.to_text(response.flags),
                                     len(response.answer),
                                     time_elapsed])
                else:
                    writer.writerow([address[0],
                                     address[1],
                                     "-",
                                     "-",
                                     "-",
                                     time_elapsed])

            def response_timeout(address):
                writer.writerow([address] + ['-']*5)

            rs = ResolversScanner(iter(self.resolvers_list),
                                  generate_query,
                                  max_pending=self.max_pending,
                                  timeout=self.request_timeout,
                                  response_received=response_received,
                                  response_timeout=response_timeout)

            rs.set_source_port(0)
            rs.run()


def read_resolvers(input_filename, ip_column):
    with open(input_filename, 'rb') as csvFile:
        reader = csv.reader(csvFile)

        for row in reader:

            try:
                address = row[ip_column].strip()
                if not address or address[0] == '(' or address == "127.0.0.1":
                    continue
                yield address
            except IndexError:
                pass


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Input filename')
    parser.add_argument('output', help='Output filename')
    parser.add_argument('-rd', type=bool, help='RD flag', default=True)
    parser.add_argument('-ipcol', type=int, help='Column of ip address in input file', default=2)
    parser.add_argument('-prefix', help='Prefix to add before .research.lab.sit.cased.de', default='1')
    parser.add_argument('-max_pending', type=int, help='Max pending requests', default=600)
    parser.add_argument('-request_timeout', type=int, help='Request timeout', default=10)
    # parser.add_argument('-ip', help='IP address of name server', default='130.83.186.149')

    args = parser.parse_args()

    domain = args.prefix + ".research.lab.sit.cased.de"
    resolvers_list = read_resolvers(args.input, args.ipcol)

    m = Main(args.output, domain, resolvers_list, args.rd, args.max_pending, args.request_timeout)
    m.run()

if __name__ == "__main__":
    main()

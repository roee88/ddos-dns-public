from dns import rrset

__author__ = 'Roee'

import csv
from resolvers_scanner import ResolversScanner
from dns_facilities import DnsFacilities


class Main:
    def __init__(self, output_filename, domains_list, recursion_desired,  max_pending, request_timeout):
        self.outputFilename = output_filename

        self.domains_list = domains_list
        self.recursion_desired = recursion_desired
        self.max_pending = max_pending
        self.request_timeout = request_timeout

    def run(self):
        with open(self.outputFilename, 'wb') as resultsFile:
            writer = csv.writer(resultsFile)

#            writer.writerow(["destip", "port", "rcode", "flags", "answers", "elapsed"])

            def generate_query(item):
                query = DnsFacilities.build_query(item, self.recursion_desired, rdtype="NS")
                dest = "127.0.0.1"  #"8.8.8.8"
                return query, dest

            def response_received(result):
                response, address, time_elapsed = result

                if response is not None and response.question:
                    domain = response.question[0].name.to_text(True)
                    for answer in response.answer:
                        for ns in answer:
                            writer.writerow((domain, ns))

            rs = ResolversScanner(iter(self.domains_list),
                                  generate_query,
                                  max_pending=self.max_pending,
                                  timeout=self.request_timeout,
                                  response_received=response_received,
                                  enable_pending=False)

            rs.set_source_port(0)
            rs.run()


def read_domains(input_filename, domain_column):
    with open(input_filename, 'rb') as csvFile:
        reader = csv.reader(csvFile)
        count = 0
        for row in reader:

            try:
                domain = row[domain_column].strip()
                if domain in ("", "localhost", "127.0.0.1", "0.0.0.0"):
                    continue
                yield domain

                count += 1
                if count > 50000:
                    break

            except IndexError:
                pass


def main():
    import argparse

    # if 1:
    #     domains_list = ["walla.co.il"]
    #     m = Main("results.txt", domains_list, True, 600, 10)
    #     m.run()
    #     return

    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Input filename')
    parser.add_argument('output', help='Output filename')
    parser.add_argument('-col', type=int, help='Column of domain in input file', default=1)
    parser.add_argument('-rd', type=bool, help='RD flag', default=True)
    parser.add_argument('-max_pending', type=int, help='Max pending requests', default=600)
    parser.add_argument('-request_timeout', type=int, help='Request timeout', default=10)

    args = parser.parse_args()
    domains_list = read_domains(args.input, args.col)
    m = Main(args.output, domains_list, args.rd, args.max_pending, args.request_timeout)
    m.run()


if __name__ == "__main__":
    main()

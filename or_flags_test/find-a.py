import dns.resolver
import argparse
import csv
import concurrent.futures
from itertools import islice


def batched_pool_runner(f, iterable, pool, batch_size):
    it = iter(iterable)
    # Submit the first batch of tasks.
    futures = set(pool.submit(f, x) for x in islice(it, batch_size))
    while futures:
        done, futures = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
        # Replenish submitted tasks up to the number that completed.
        futures.update(pool.submit(f, x) for x in islice(it, len(done)))
        for d in done:
            yield d


def read_domains(input_filename):
    with open(input_filename, 'rb') as csvFile:
        reader = csv.reader(csvFile)

        for row in reader:
            (rdomain, ns) = row
            domain = ns.strip()
            if domain:
                yield rdomain, ns, domain


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Input filename')
    parser.add_argument('output', help='Output filename')
    parser.add_argument('-max_workers', type=int, help='Concurrency value', default=100)
    args = parser.parse_args()

    domains = read_domains(args.input)

    def single_query(params):
        rdomain, ns, domain = params

        try:
            return rdomain, ns, dns.resolver.query(domain, 'A')
        except Exception, e:
            print e

        return rdomain, ns, None

    with open(args.output, 'wb') as resultsFile:
        writer = csv.writer(resultsFile)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            for future in batched_pool_runner(single_query, domains, executor, args.max_workers):
                rdomain, ns, answers = future.result()
                if answers:
                    for a in answers:
                        # print rdomain,':', ns, ':', a
                        writer.writerow((rdomain, ns, str(a)))

if __name__ == '__main__':
    main()

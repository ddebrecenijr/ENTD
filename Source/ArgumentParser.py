import argparse

__author__ = "David Debreceni Jr"

class ArgParser:
    def __init__(self):
        self.args = self.__build_args()

    def __build_args(self):
        ap = argparse.ArgumentParser()
        ap.add_argument('-f', help='Name of PCAP File', required=True, nargs='?')
        ap.add_argument('-p', help='Ports', required=False, nargs='?')
        ap.add_argument('-u', help='Update Domain JSON List', required=False, nargs='?')
        ap.add_argument('-s', help='Number of Threads, Defaults to 10', required=False, nargs='?', type=int)
        ap.add_argument('-i', help='Number of Domains to Analyze, Defaults to 10k', required=False, nargs='?', type=int)

        return ap.parse_args()

    def parse_args(self):
        """
        Parses Arguments passed in to the command prompt
        :return:
        """
        return dict(
            file=self.args.f,
            ports=self.args.p,
            update=self.args.u or False,
            threads=self.args.s or 10,
            num_domains=self.args.i or 10000
        )
import argparse


class ArgParser:
    def __init__(self):
        self.args = self.__build_args()

    def __build_args(self):
        ap = argparse.ArgumentParser()
        ap.add_argument('-f', help='Name of PCAP File', required=True, nargs='?')
        ap.add_argument('-p', help='Ports', required=False, nargs='?')

        return ap.parse_args()

    def parse_args(self):
        """
        Parses Arguments passed in to the command prompt
        :return:
        """
        return dict(
            file=self.args.f,
            ports=self.args.p
        )
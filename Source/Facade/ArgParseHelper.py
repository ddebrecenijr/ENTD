import argparse

__author__ = "David Debreceni Jr"

class ArgParseHelper(object):
    """
    ArgParseHelper is used for passing in command line arguments to be used for the program.
    Current Commmands are as follows:
    -f  Name of the PCAP File           REQUIRED = TRUE     Takes any number of files       No Default
    -p  Ports to be looked at           REQUIRED = FALSE    Takes any number of ports       Default is 443
    -u  Update Domain JSON List         REQUIRED = FALSE    Takes 1 argument True or False  Defaults to False
    -s  Number of Threads               REQUIRED = FALSE    Takes 1 argument                Defaults to 10
    -i  Number of Domains to Analyze    REQUIRED = FALSE    Takes 1 argumetn                Defaults to 10k
    """

    def __init__(self):
        self.args = self.__build_args()

    def __build_args(self):
        ap = argparse.ArgumentParser()
        ap.add_argument('-f', help='Name of PCAP File', required=False, nargs='?')
        ap.add_argument('-p', help='Ports', required=False, nargs='?')
        ap.add_argument('-u', help='Update Domain JSON List', required=False, nargs=1)
        ap.add_argument('-s', help='Number of Threads, Defaults to 10', required=False, nargs=1, type=int)
        ap.add_argument('-i', help='Number of Domains to Analyze, Defaults to 10k', required=False, nargs=1, type=int)

        return ap.parse_args()

    def parse_args(self):
        """
        Parses Arguments passed in to the command prompt
        Keys: file, ports, update, threads, num_domains
        :return: Dictionary containing keywords for parsed Arguments
        """
        return dict(
            file=self.args.f,
            ports=self.args.p,
            update=self.args.u or False,
            threads=self.args.s or 10,
            num_domains=self.args.i or 10000
        )
import sys
import re
import socket
import ssl
from multiprocessing.pool import ThreadPool as Pool
import json

__author__ = "David Debreceni Jr"

class Extractor():
    def __init__(self):
        self.pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'

    def domain_reader(self, file):
        """
        Extracts all domains from given file.
        :param file: File of any type containing any amount of domains
        :return: None
        """
        try:
            with open(file, 'r') as domain_file:
                return re.findall(self.pattern, domain_file.read())
        except FileNotFoundError:
            print(f'{file} was not found.')
            sys.exit()

    def extract_data(self, domain):
        """
        Extracts IP Address, CipherSuite, and SSL Version of Domain over port 443 and stores into a dictionary
        :param domain: Domain Name
        :return: Dictionary containing info
        """

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            ssl_sock = ssl.wrap_socket(sock)
            ssl_sock.connect((domain, 443))

            domain_info = {
                "source_ip": ssl_sock.getpeername()[0],
                "destination_ip": None,
                "source_port": 443,
                "destination_port": None,
                "version": ssl_sock.version(),
                "selected_ciphersuite": ssl_sock.cipher()[0]
            }
            ssl_sock.close()
            return domain_info
        except ssl.SSLError:
            print(f'{domain} failed to connect, ssl error.')
        except(TimeoutError, socket.timeout):
            print(f'{domain} connection attempt failed due to timeout.')
        except socket.gaierror:
            print(f'{domain} getaddrinfo failed.')
        except ConnectionRefusedError:
            print(f'{domain} refused connection.')
        except ConnectionResetError:
            print(f'{domain} connection forcibly closed.')

    def multiprocess_extraction(self, domains, num_threads=10):
        """
        Uses Multiprocessing Pool to quickly extract information
        :param domains: List of Domains
        :param num_threads: Number of Threads requested, defaults to 10
        :return:
        """

        pool = Pool(num_threads)
        return json.dumps(pool.map(self.extract_data, domains))
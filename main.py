#!/usr/bin/env python3

from Source.ArgumentParser import ArgParser
from Source.ProcessPacket import ProcessPacket
from Source.DomainInfoExtractor import Extractor
import json

__author__ = "David Debreceni Jr"

def main():
    arg_parser = ArgParser()
    kwargs = arg_parser.parse_args()
    if kwargs['update']:
        domain_extractor = Extractor()
        domains = domain_extractor.domain_reader('Source/one_million_domains.txt')
        json_output = domain_extractor.multiprocess_extraction(domains[:kwargs['num_domains']], kwargs['threads'])
        with open('JSON/benign_domain_dump.json', 'w') as file:
            file.write(json_output)

    process_packet = ProcessPacket(kwargs['file'], kwargs['ports'])
    json_output = json.dumps(process_packet.get_server_hello_data())

    # For now we will write the json dumps to a file
    with open('JSON/server_hello_dump.json', 'w') as file:
        file.write(json_output)

if __name__ == "__main__":
    main()

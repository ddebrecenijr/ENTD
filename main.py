#!/usr/bin/env python3

from Source.Facade.ArgParseHelper import ArgParseHelper
from Source.ProcessPacket import ProcessPacket
from Source.DomainInfoExtractor import Extractor
from Source.SVMModel import SVMModel
import json

__author__ = "David Debreceni Jr"


def main():
    arg_parser = ArgParseHelper()
    kwargs = arg_parser.parse_args()
    #if kwargs['update']:
    #    # Handling Benign Domains
    #    domain_extractor = Extractor()
    #    benign_domains = domain_extractor.domain_reader('Source/benign_domains.txt')
    #    json_output = domain_extractor.multiprocess_extraction(
    #        benign_domains[:kwargs['num_domains']], kwargs['threads']
    #    )
    #    with open('JSON/benign_domain_dump.json', 'w') as file:
    #        file.write(json_output)

    #    # Handling Malicious Domains
    #    malicious_domains = domain_extractor.domain_reader('Source/malicious_domains.txt')
    #    json_output = domain_extractor.multiprocess_extraction(
    #        malicious_domains[:kwargs['num_domains']], kwargs['threads']
    #    )
    #    with open('JSON/malicious_domain_dump.json', 'w') as file:
    #        file.write(json_output)

    svm = SVMModel()
    svm.train_model()
    #print(svm.model_accuracy())
    #svm.show()

    #if 'malicious' in kwargs['file']:
    #    with open('JSON/malicious_test.json', 'r') as file:
    #        json_output = file.read()
    #else:
    #    process_packet = ProcessPacket(kwargs['file'], kwargs['ports'])
    #    json_output = json.dumps(process_packet.get_server_hello_data())

    #svm.test_model(json_output)

    #svm.show()


if __name__ == "__main__":
    main()

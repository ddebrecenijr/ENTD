#!/usr/bin/env python3.6

from Source.Facade.ArgParseHelper import ArgParseHelper
from Source.ProcessPacket import ProcessPacket
from Source.DomainInfoExtractor import Extractor
from Source.SVMModel import SVMModel
import json
import sys

import socket
from Source.Sniffer.ethernet import Ethernet
from Source.Sniffer.ipv4 import IPv4
from Source.Sniffer.tcp import TCP
from Source.Sniffer.ssl import RecordProtocol, ServerHello

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

#    svm = SVMModel()
#    svm.train_model()
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

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x003))
    while True:
        try:
            raw_buffer = sniffer.recvfrom(65565)[0]

            ethernet = Ethernet(raw_buffer[0:14])
            if ethernet.Type == 'IPv4':
                ip = IPv4(raw_buffer[14:34])
                if ip.Protocol == "TCP":
                    tcp = TCP(raw_buffer[34:])
                    rec = RecordProtocol(raw_buffer[34+tcp.Data_Offset:39+tcp.Data_Offset])
                    server = ServerHello(raw_buffer[39+tcp.Data_Offset:])

                    if server.Handshake_Type == "Server_Hello":

                        print('--- ETHERNET FRAME ---')
                        print(f'Destination Address: {ethernet.Destination_Address}')
                        print(f'Source Address: {ethernet.Source_Address}')
                        print(f'Type: {ethernet.Type}')

                        print('--- IPv4 FRAME ---')
                        print(f'Version: {ip.Version}')
                        print(f'IP Header Length: {ip.IP_Header_Length}')
                        print(f'Type of Service: {ip.Type_of_Service}')
                        print(f'Total Length: {ip.Total_Length}')
                        print(f'Identification: {ip.Identification}')
                        print(f'Time to Live: {ip.Time_to_Live}')
                        print(f'Protocol: {ip.Protocol}')
                        print(f'Header Checksum: {ip.Header_Checksum}')
                        print(f'Source Address: {ip.Source_Address}')
                        print(f'Destination Address: {ip.Destination_Address}')

                        print('--- TCP FRAME ---')
                        print(f'Source Port: {tcp.Source_Port}')
                        print(f'Destination Port: {tcp.Destination_Port}')

                        print('--- RECORD PROTOCOL ---')
                        print(f'Content Type: {rec.Content_Type}')
                        print(f'Version: {rec.Version}')
                        print(f'Length: {rec.Length}')

                        print('--- SERVER HELLO ---')
                        print(f'Handshake Type: {server.Handshake_Type}')
                        print(f'Length: {server.Length}')
                        print(f'Version: {server.Version}')
                        print(f'Random: {server.Random}')
                        print(f'Session ID Length: {server.Session_ID_Length}')
                        print(f'Selected CipherSuite: {server.Cipher_Suite}')

        except ValueError as e:
            continue
        except KeyboardInterrupt:
            sys.exit()
if __name__ == "__main__":
    main()

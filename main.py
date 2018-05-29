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

import tempfile
import ast

__author__ = "David Debreceni Jr"


def main():
    print('Training Model...')
    print('This may take a bit...')
    svm = SVMModel()
    svm.train_model()
    print(svm.model_accuracy())
    print('Training Complete!')

    print('Starting Sniffer.')
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x003))
    print('Sniffer Created!')
    print('Please browse the internet as you see fit.')
    data = []
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
                        data.append([server.Version, server.Cipher_Suite])
                        
                        #svm.test_model(server.Version, server.Cipher_Suite)


        except ValueError as e:
            continue
        except KeyboardInterrupt:
            svm.test_model(data)
            if input() == 'q':
                sys.exit()
            else:
                data = []
                continue

if __name__ == "__main__":
    main()

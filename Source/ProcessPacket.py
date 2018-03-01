#!/usr/bin/env python

import dpkt

__author__ = "David Debreceni Jr"

class ProcessPacket:
    def __init__(self, packet, *ports):
        self.packet = packet
        self.ports = ports
        self.__read()

    def __read(self):
        with open(self.packet, 'rb') as pcap:
            try:
                self.pcap = dpkt.pcap.Reader(pcap)
            except ValueError as error:
                raise Exception(f'{self.packet} is not a valid PCAP: {error}')

    def process_packet(self):
        """
        Process Packets within the PCAP file
        :return: None
        """
        for timestamp, buf in self.pcap:
            eth = dpkt.ethernet.Ethernet(buf)


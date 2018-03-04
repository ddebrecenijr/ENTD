#!/usr/bin/env python

import dpkt
import socket

__author__ = "David Debreceni Jr"


class ProcessPacket:
    def __init__(self, packet, *ports):
        self.packet = packet
        self.ports = ports
        self.pcap = None
        self.__read()

        self.ssl = 443
        self.handshake = 22


    def __read(self):
        pcap = open(self.packet, 'rb')
        try:
            self.pcap = dpkt.pcap.Reader(pcap)
        except ValueError as error:
            raise Exception(f'{self.packet} is not a valid PCAP: {error}')

    def __convert_ip(self, ip):
        try:
            return socket.inet_ntop(socket.AF_INET, ip)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, ip)

    def get_server_hello_data(self):
        """
        Looks through Packet file finding all traces of Server Hello Messages over port 443 and any additional ports
        passed into the class.
        :return: List of Records containing;
        Source IP, Destination IP, Source Port, Destination Port, Version, & Selected CipherSuite
        """
        results = []
        for timestamp, buf in self.pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP) or not isinstance(eth.data.data, dpkt.tcp.TCP):
                continue

            ip = eth.data
            tcp = ip.data

            if not (tcp.dport == self.ssl or tcp.sport == self.ssl or self.ports) or len(tcp.data) <= 0:
                continue

            tls_handshake = bytearray(tcp.data)
            if tls_handshake[0] != self.handshake:
                continue

            try:
                records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
            except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData):
                continue

            if len(records) <= 0:
                continue

            for record in records:
                if record.type != self.handshake or len(record.data) == 0:
                    continue

                server_hello = bytearray(record.data)
                if server_hello[0] != 2:
                    continue
                try:
                    handshake = dpkt.ssl.TLSHandshake(record.data)
                except dpkt.dpkt.NeedData:
                    continue
                if not isinstance(handshake.data, dpkt.ssl.TLSServerHello):
                    continue

                server_handshake = handshake.data

                record = {
                    "source_ip": self.__convert_ip(ip.src),
                    "destination_ip": self.__convert_ip(ip.dst),
                    "source_port": tcp.sport,
                    "destination_port": tcp.dport,
                    "version": hex(server_handshake.version),
                    "selected_ciphersuite": hex(server_handshake.cipher_suite)
                }
                results.append(record)
        return results




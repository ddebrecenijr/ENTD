from ctypes import *
import binascii
import Source\Abstract\TLSHelper

__author__ = "David Debreceni Jr"

"""
Convert SSL/TLS Record Protocol bytes to more readable class.
"""

class RecordProtocol(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("type", c_ubyte),
        ("version", c_ushort),
        ("len", c_ushort)
    ]

    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        self.record_types = {
            0x14 : "Change_Cipher_Spec",
            0x15 : "Alert",
            0x16 : "Handshake",
            0x17 : "Application_Data"
        }

    @property
    def Content_Type(self):
        return self.record_types[self.type]

    @property
    def Version(self):
        return VERSIONS[self.version]

    @property
    def Length(self):
        return self.len

class Server_Hello(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("type", c_ubyte),
        ("len", c_char*3),
        ("version", c_ushort),
        ("random", c_char * 32),
        ("session_id_length", c_ubyte),
        ("cipher_suite", c_ushort)
    ]
    
    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        pass

    @property
    def Handshake_Type(self):
        return TLSHelper.HANDSHAKE_TYPES.get(self.type)

    @property
    def Length(self):
        return int(self.len)

    @property
    def Version(self):
        return TLSHelper.TLS_VERSIONS.get(self.version)

    @property
    def Random(self):
        return binascii.hexlify(self.random)

    @property
    def Session_ID_Length(self):
        return self.session_id_length

    @property
    def Cipher_Suite(self):
        return TLSHelper.CIPHERSUITES[self.cipher_suite][0]



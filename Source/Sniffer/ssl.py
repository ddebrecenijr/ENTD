from ctypes import *
import binascii
from Source.Abstract import TLSHelper

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
        try:
            return self.record_types[self.type]
        except KeyError:
            pass

    @property
    def Version(self):
        try:
            return TLSHelper.TLS_VERSIONS[self.version]
        except KeyError:
            pass

    @property
    def Length(self):
        return self.len

class ServerHello(BigEndianStructure):
    _fields_ = [
        ("type", c_ubyte),
        ("len", c_char*3),
        ("version", c_ushort),
        ("random", c_char * 32),
        ("session_id_length", c_ubyte)
    ]
    
    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        self.data = data

    @property
    def Handshake_Type(self):
        print(self.type)
        return TLSHelper.HANDSHAKE_TYPES.get(self.type)

    @property
    def Length(self):
        return self.len
    @property
    def Version(self):
        self.version

    @property
    def Random(self):
        return binascii.hexlify(self.random)

    @property
    def Session_ID_Length(self):
        return self.session_id_length

    @property
    def Session_ID(self):
        if self.session_id_length != 0:
            class Session(BigEndianStructure):
                _fields_ = [
                    ("session_id", c_char * self.session_id_length)
                ]

                def __new__(self, data=None):
                    return self.from_buffer_copy(data)

                def __init__(self, data=None):
                    pass

                @property
                def Session_ID(self):
                    return self.session_id

            return binascii.hexlify(Session(self.data[39:]).Session_ID)
        else:
            return None

    @property
    def Cipher_Suite(self):
        class Cipher(BigEndianStructure):
            _fields_ = [
                ("cipher", c_ushort)
            ]

            def __new__(self, data=None):
                return self.from_buffer_copy(data)

            def __init__(self, data=None):
                pass

            @property
            def Cipher_Suite(self):
                return self.cipher
        return Cipher(self.data[39 + 32:])
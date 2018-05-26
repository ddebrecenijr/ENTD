from ctypes import *

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

class Handshake_Protocol(Structure):
    _fields_ = [
        ("type", c_ubyte)
    ]

    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        pass

    @property
    def Type(self):
        try:
            return eval(HANDSHAKE_TYPES.get(self.type))
        except NameError:
            return None

class Client_Hello(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("len", c_uint, 24),
        ("version", c_ushort),
        ("random", c_char * 32),
        ("session_id_len", c_ubyte),
        ("cipher_suites_len", c_ushort)
    ]

    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        pass

    @property
    def Handshake_Type(self):
        return HANDSHAKE_TYPES.get(self.type)

    @property
    def Length(self):
        return __shift_right(self.len, 1)

    @property
    def Version(self):
        return VERSIONS.get(self.version)

    @property 
    def Random(self):
        return self.random

    @property
    def Session_ID_Length(self):
        return self.session_id_length

    @property
    def Cipher_Suites_Length(self):
        return self.cipher_suites_len

    @property
    def Cipher_Suites(self):
        class CipherSuites(Structure):
            _fields_ = [("cipher_suites", c_char * self.cipher_suites_len)]

            def __new__(self, data=None):
                return self.from_buffer_copy(data)

            def __init__(self, data=None):
                pass

            @property
            def Cipher_Suites(self):
                return self.cipher_suites

        return CipherSuites(data[26:]).Cipher_Suites

class Server_Hello(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("len", c_uint, 24),
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
        return HANDSHAKE_TYPES.get(self.type)

    @property
    def Length(self):
        return __shift_right(self.len, 1)

    @property
    def Version(self):
        return VERSIONS.get(self.version)

    @property
    def Random(self):
        return self.random

    @property
    def Session_ID_Length(self):
        return self.session_id_length

    @property
    def Cipher_Suite(self):
        return self.cipher_suite

VERSIONS = {
    0x0300 : "SSLv3",
    0x0301 : "TLSv1",
    0x0302 : "TLSv1.1",
    0x0303 : "TLSv1.2"
}

HANDSHAKE_TYPES = {
    0x00 : "Hello_Request",
    0x01 : "Client_Hello", 
    0x02 : "Server_Hello", 
    0x0b : "Certificate", 
    0x0c : "Server_Key_Exchange",
    0x0d : "Certificate_Request",
    0x0e : "Server_Done",
    0x0f : "Certificate_Verify",
    0x10 : "Client_Key_Exchange",
    0x14 : "Finished"
}

def __shift_right(data, n):
    """
    Shift the data, n bytes to the right
    :param data: Data to be shifted
    :param n: Bytes to be shifted by
    :return: Shifted data
    """
    return (data >> (8 * n))

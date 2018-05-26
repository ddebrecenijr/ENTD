from ctypes import *

__author__ = "David Debreceni Jr"

class Ethernet(BigEndianStructure):
    _fields_ = [
            ("dest", c_char*6),
            ("src", c_char*6),
            ("type", c_ushort)
    ]

    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        pass

    @property
    def Destination_Address(self):
        return self.__get_mac_addr(self.dest)

    @property
    def Source_Address(self):
        return self.__get_mac_addr(self.src)

    @property
    def Type(self):
        return hex(self.type)

    def __get_mac_addr(self, raw):
        return ':'.join(map('{:02x}'.format, raw)).upper()

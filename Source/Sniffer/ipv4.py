import socket
import struct
from ctypes import *

__author__ = "David Debreceni Jr"

"""
Convert the IPv4 header from its bytes into a more readable class.
"""
class IPv4(BigEndianStructure):
	_fields_ = [
		("version", c_ubyte, 4),
		("ihl", c_ubyte, 4),
		("tos", c_ubyte),
		("len", c_ushort),
		("id", c_ushort),
		("offset", c_ushort),
		("ttl", c_ubyte),
		("proto", c_ubyte),
		("check", c_ushort),
		("src", c_uint),
		("dest", c_uint)
	]

	def __new__(self, data=None):
		return self.from_buffer_copy(data)

	def __init__(self, data=None):
		self.protocol_map = { 6 : "TCP" }

	@property
	def Version(self):
		# 4 bits
		return self.version

	@property
	def IP_Header_Length(self):
		# 4 bits
		return self.ihl

	@property
	def Type_of_Service(self):
		# 8 bits
		return self.tos

	@property
	def Total_Length(self):
		# 16 bits
		return self.len

	@property
	def Identification(self):
		# 16 bits
		return self.id

	@property
	def Time_to_Live(self):
		# 8 bits
		return self.ttl

	@property
	def Protocol(self):
		# 8 bits
        # Convert to readable Protocol
		try:
			return self.protocol_map[self.proto]
		except:
			return str(self.proto)

	@property
	def Header_Checksum(self):
		# 16 bits
		return self.check

	@property
	def Source_Address(self):
		# 32 bits
        # Converting to readable IP Address
		return socket.inet_ntoa(struct.pack("<L", self.src)[::-1])

	@property
	def Destination_Address(self):
		# 32 bits
		return socket.inet_ntoa(struct.pack("<L", self.dest)[::-1])
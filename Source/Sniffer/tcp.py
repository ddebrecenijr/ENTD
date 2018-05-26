import struct
from ctypes import *

__author__ = "David Debreceni Jr"

"""
Convert the TCP Header from its bytes into a more readable class.
"""
class TCP(BigEndianStructure):
	_pack_ = 1
	_fields_ = [
		("src", c_ushort),
		("dest", c_ushort),
		("seq", c_uint),
		("ack", c_uint),
		("off", c_ubyte, 4),
		("res", c_ubyte, 3),
		("ns", c_ubyte, 1),
		("cwr", c_ubyte, 1),
		("ece", c_ubyte, 1),
		("urg", c_ubyte, 1),
		("ack", c_ubyte, 1),
		("psh", c_ubyte, 1),
		("rst", c_ubyte, 1),
		("syn", c_ubyte, 1),
		("fin", c_ubyte, 1),
		("win", c_ushort),
		("check", c_ushort),
		("urgp", c_ushort)
	]

	def __new__(self, data=None):
		return self.from_buffer_copy(data)

	def __init__(self, data=None):
		pass

	@property
	def Source_Port(self):
		return int(self.src)

	@property
	def Destination_Port(self):
		return int(self.dest)

	@property
	def Sequence_Number(self):
		return int(self.seq)

	@property
	def Acknowledgment_Number(self):
		return self.ack

	@property
	def Data_Offset(self):
		return self.off

	@property
	def Reserved(self):
		return self.res

	@property
	def NS_Flag(self):
		return self.ns

	@property
	def CWR_Flag(self):
		return self.cwr

	@property
	def ECE_Flag(self):
		return self.ece

	@property
	def URG_Flag(self):
		return self.urg

	@property
	def ACK_Flag(self):
		return self.ack

	@property
	def PSH_Flag(self):
		return self.psh

	@property
	def RST_Flag(self):
		return self.rst

	@property
	def SYN_Flag(self):
		return self.syn

	@property
	def FIN_Flag(self):
		return self.fin

	@property
	def Window_Size(self):
		return self.win

	@property
	def Checksum(self):
		return self.check

	@property
	def Urgent_Pointer(self):
		return self.urgp

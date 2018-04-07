import socket

__author__ = "Sneh Patel"

class Socket(object):
    """
    A Facade for the library Socket
    """
    def __init__(self):
        """
        Creates an INET and Streaming Socket.
        :param: None
        :return: Socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)


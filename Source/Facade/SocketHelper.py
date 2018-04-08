import socket

__author__ = "Sneh Patel, Bryan Chen"

class SocketHelper(object):
    """
    A Facade for the library Socket
    """
    def __init__(self, sock=None):
        """
        Creates an INET and Streaming Socket.
        :param: None
        :return: Socket
        """
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def sock_convert_ip(self, ip):
        try:
            return socket.inet_ntop(socket.AF_INET, ip)
        except ValueError:
    return socket.inet_ntop(socket.AF_INET6, ip)


    def socket(self, domain):
        """
        Establish the new connection and timeout
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
        """
        Error Handling
        """
        except(TimeoutError, socket.timeout):
            print(f'{domain} connection attempt failed due to timeout.')
        except socket.gaierror:
            print(f'{domain} getaddrinfo failed.')
        except ConnectionRefusedError:
            print(f'{domain} refused connection.')
        except ConnectionResetError:
            print(f'{domain} connection forcibly closed.')

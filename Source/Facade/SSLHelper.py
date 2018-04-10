import ssl

__author__ = "Sneh Patel"

class SSL(object):
    """
    A Facade for the library SSL
    """
    def __init__(self):
        pass

    def SSL(self, domain):
        """
        Returns Dictionary containing info
        :param domain: Domain Name
        :return: Dictionary containing info
        """
        try:
            ssl_sock = ssl.wrap_socket(Socket)
            ssl_sock.connect((domain, 443))
            
            domain_info = {
                    "source_ip": ssl_sock.getpeername()[0],
                    "destination_ip": None, 
                    "source_port": 443,
                    "destination_port": None, 
                    "version": ssl_sock.version(), 
                    "selected_ciphersuite": ssl_sock.cipher()[0]
                    }

            ssl_sock.close()
            return domain_info

        #Error handling below
        
        except ssl.SSLError:
            print(f'{domain} failed to connect, ssl error.')
        except ConnectionRefusedError:
            print(f'{domain} refused connection.')
        except ConnectionResetError:
            print(f'{domain} connection forcibly closed.')

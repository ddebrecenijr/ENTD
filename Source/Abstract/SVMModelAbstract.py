from abc import ABC

__author__ = "David Debreceni Jr"

class SVM_Model_Abstract(ABC):
    def __init__(self):
        self.source_ip_index = 1
        self.dest_ip_index = 1
        self.source_port_index = 1
        self.dest_port_index = 1
        self.version_index = 1
        self.cipher_dict = 1

        self.source_ip_dict = {}
        self.dest_ip_dict = {}
        self.source_port_dict = {}
        self.dest_port_dict = {}
        self.version_dict = {}
        self.cipher_dict = {}

    # Indexes

    @property
    def source_ip_index(self):
        return self.__source_ip_index

    @source_ip_index.setter
    def source_ip_index(self, x):
        self.__source_ip_index = x

    @property
    def dest_ip_index(self):
        return self.__dest_ip_index

    @dest_ip_index.setter
    def dest_ip_index(self, x):
        self.__dest_ip_index = x

    @property
    def source_port_index(self):
        return self.__source_port_index

    @source_port_index.setter
    def source_port_index(self, x):
        self.__source_port_index = x

    @property
    def dest_port_index(self):
        return self.__dest_port_index

    @dest_port_index.setter
    def dest_port_index(self, x):
        self.__dest_port_index = x

    @property
    def version_index(self):
        return self.__version_index

    @version_index.setter
    def version_index(self, x):
        self.__version_index = x

    @property
    def cipher_index(self):
        return self.__cipher_index

    @cipher_index.setter
    def cipher_index(self, x):
        self.__cipher_index = x

    # Dictionaries

    @property
    def source_ip_dict(self):
        return self.__source_ip_dict

    @source_ip_dict.setter
    def source_ip_dict(self, x):
        self.__source_ip_dict.update(x)

    @property
    def dest_ip_dict(self):
        return self.__dest_ip_dict

    @dest_ip_dict.setter
    def dest_ip_dict(self, x):
        self.__dest_ip_dict.update(x)

    @property
    def source_port_dict(self):
        return self.__source_port_dict

    @source_port_dict.setter
    def source_port_dict(self, x):
        self.__source_port_dict.update(x)

    @property
    def dest_port_dict(self):
        return self.__dest_port_dict

    @dest_port_dict.setter
    def dest_port_dict(self, x):
        self.__dest_port_dict.update(x)

    @property
    def version_dict(self):
        return self.__version_dict

    @version_dict.setter
    def version_dict(self, x):
        self.version_dict.update(x)

    @property
    def cipher_dict(self):
        return self.__cipher_dict

    @cipher_dict.setter
    def cipher_dict(self, x):
        self.__cipher_dict.update(x)
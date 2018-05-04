from abc import ABC

__author__ = "Sneh Patel"

class Domain_Info_Extractor_Abstract(ABC):
    def __init__(self):
        self.file_index = 1
        self.domain_index = 1
        self.domains_index = 1
        self.num_threads_index = 1

        self.file_dict = {}
        self.domain_dict = {}
        self.domains_dict = {}
        self.num_threads_dict = {}
    
    #Indexes

    @property
    def file_index(self):
        return self.__file_index

    @file_index.setter
    def file_index(self,x):
        self.__file_index = x

    @property
    def domain_index(self):
        return self.__domain_index 

    @domain_index.setter
    def domain_index(self,x):
        self.__domain_index = x

    @property
    def domains_index(self):
        return self.__domains_index

    @domains_index.setter
    def domains_index(self,x):
        self.__domains_index = x

    @property
    def num_threads_index(self):
        return self.__num_threads_index

    @num_threads_index.setter
    def num_threads_index(self, x):
        self.__num_threads_index = x

    #Dictionaries
    
    @property
    def file_dict(self):
        return self.__file_dict

    @file_dict.setter
    def file_dict(self,x):
        self.__file_dict.update(x)

    @property
    def domain_dict(self):
        return self.__domain_dict

    @domain_dict.setter
    def domain_dict(self,x):
        self.__domain_dict.update(x)

    @property
    def domains_dict(self):
        return self.__domains_dict

    @domains_dict.setter
    def domains_dict(self,x):
        self.__domains_dict.update(x)

    @property
    def num_threads_dict(self):
        return self.__num_threads_dict

    @num_threads_dict.setter
    def num_threads_dict(self,x):
        self.__num_threads_dict.update(x)


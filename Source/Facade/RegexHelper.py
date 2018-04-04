import re

__author__ = "David Debreceni Jr"

__pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'

class RegexHelper(object):
    """
    A Façade for the library re
    """
    def __init__(self):
        pass

    """
    Find all domains in a string.
    :param str: String containing domains
    :return: Any domains found
    """
    def extract_all_domains(self, str):
        return re.findall(__pattern, str)
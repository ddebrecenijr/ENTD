from mlxtend.plotting import plot_decision_regions
from sklearn import svm

import math
import numpy as np
import random

__author__ = "David Debreceni Jr"

class SVM_Model:
    """
    Train and Implement a Support Vector Machine Model using features:
    TLS Version; Selected CipherSuite;
    """

    def __init__(self, sql_helper):
        self.sql_helper = sql_helper
        self.benign_data = self.__load_benign_data()
        self.malicious_data = self.__load_malicious_data()

    def __load_benign_data(self):
        try:

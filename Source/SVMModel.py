from Source.SQL.SqlHelper import SQL_Helper
from mlxtend.plotting import plot_decision_regions
from sklearn.svm import SVC

import math
import matplotlib.pyplot as plt
import numpy
import random

__author__ = "David Debreceni Jr"

class SVMModel:
    """
    Train and Implement a Support Vector Machine Model using features:
    TLS Version; Selected CipherSuite;
    """

    def __init__(self):
        self.__source_ip_index = 1
        self.__dest_ip_index = 1
        self.__source_port_index = 1
        self.__dest_port_index = 1
        self.__version_index = 1
        self.__cipher_index = 1

        self.__source_ip_dict = {}
        self.__dest_ip_dict = {}
        self.__source_port_dict = {}
        self.__dest_port_dict = {}
        self.__version_dict = {}
        self.__cipher_dict = {}

        self.sql_helper = SQL_Helper()
        self.benign_data = self.__load_data("benign_domains")
        self.malicious_data = self.__load_data("malicious_domains")
        self.data_set = []
        self.__extract_features(self.benign_data, 0)
        self.__extract_features(self.malicious_data, 1)

        self.model = SVC()
        self.train_sample_x = None
        self.train_sample_y = None
        self.train_means = None
        self.train_std = None
        self.train_sample_x = None
        self.train_sample_y = None
        self.predicted = None

    def __load_data(self, table_name):
        try:
            return self.sql_helper.read_all_from_table(table_name)
        except Exception as error:
            print(f'{error}')
    
    def __extract_features(self, data, y_val):
        for x in data:
            temp = []
            try:
                if x['Version'] not in self.__version_dict:
                    self.__version_dict.update({x['Version']: self.__version_index})
                    temp.append(self.__version_index)
                    # Update Index after adding to dictionary
                    self.__version_index += 1
                else:
                    temp.append(self.__version_dict.get(x['Version']))

                if x['CipherSuite'] not in self.__cipher_dict:
                    self.__cipher_dict.update({x['CipherSuite']: self.__cipher_index})
                    temp.append(self.__cipher_index)
                    self.__cipher_index += 1
                else:
                    temp.append(self.__cipher_dict.get(x['CipherSuite']))
                temp.append(y_val)
                self.data_set.append(temp)
            except TypeError:
                continue

    def __standardize(self, data, mean=None, std=None):
        if mean is None and std is None:
            means = numpy.mean(data, axis=0)
            stds = numpy.std(data, axis=0)

            for i in range(len(data)):
                for j in range(len(data[i])):
                    data[i][j] = (data[i][j] - means[j]) / stds[j]

            return data, means, stds
        else:
            for i in range(len(data)):
                for j in range(len(data[i])):
                    data[i][j] = (data[i][j] - mean[j]) / std[j]
            return data

    def train_model(self):
        random.seed(0)
        random.shuffle(self.data_set)
        train_size = math.ceil(len(self.data_set)*(2/3))

        self.train_sample_x, self.train_means, self.train_std = self.__standardize(
            [row[:-1] for row in self.data_set[:train_size]]
            )

        self.train_sample_y = [row[-1] for row in self.data_set[:train_size]]

        self.test_sample_x = self.__standardize(
            [row[:-1] for row in self.data_set[train_size:]],
            self.train_means,
            self.train_std
            )

        self.test_sample_y = [row[-1] for row in self.data_set[train_size:]]
        
        self.model.fit(self.train_sample_x, self.train_sample_y)

    def model_accuracy(self):
        self.predicted = self.model.predict(self.test_sample_x)

        TP = 0
        TN = 0
        FP = 0
        FN = 0

        for i in range(len(self.predicted)):
            if self.test_sample_y[i] == 0:
                if self.test_sample_y[i] == self.predicted[i]:
                    TP += 1
                else:
                    FN += 1
            elif self.test_sample_y[i] == 1:
                if self.test_sample_y[i] == self.predicted[i]:
                    TN += 1
                else:
                    FP += 1

        accuracy = (TP+TN)/(TP+TN+FP+FN)
        return accuracy*100

    def show(self):
        x = numpy.array(self.train_sample_x)
        y = numpy.array(self.train_sample_y)
        plot_decision_regions(X=x, y=y, clf=self.model)
        plt.xlabel('SSL/TLS Version')
        plt.ylabel('Selected CipherSuite')
        plt.title('SVM Decision Region Boundary')
        plt.show()

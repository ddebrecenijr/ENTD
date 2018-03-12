import json
from sklearn import svm
import numpy
from mpl_toolkits import mplot3d
import matplotlib.pyplot as plt
import random
import math

__author__ = "David Debreceni Jr"


class SVMModel:
    def __init__(self, benign_file, malicious_file):
        self.benign_file = benign_file
        self.malicious_file = malicious_file
        self.benign_data = self.__load_data(benign_file)
        self.malicious_data = self.__load_data(malicious_file)
        self.data_set = []
        self.__extract_features()
        self.model = None
        self.train_sample_x = None
        self.train_sample_y = None
        self.train_means = None
        self.train_std = None
        self.test_sample_x = None
        self.test_sample_y = None
        self.predicted = None

    def __load_data(self, file):
        try:
            return json.load(open(file, 'r'))
        except json.JSONDecodeError:
            print(f'{file} is not a valid JSON file.')
        except FileNotFoundError:
            print(f'{file} was not found.')

    def __extract_features(self):
        source_ip_index = 1
        source_ip_dict = {}

        dest_ip_index = 1
        dest_ip_dict = {}

        source_port_index = 1
        source_port_dict = {}

        dest_port_index = 1
        dest_port_dict = {}

        self.version_index = 1
        self.version_dict = {}

        self.cipher_index = 1
        self.cipher_dict = {}

        for data in self.benign_data:
            try:
                temp_data = []
                # # Handle the Source IP Address Feature
                # if data['source_ip'] not in source_ip_dict:
                #     source_ip_dict.update({data['source_ip']: source_ip_index})
                #     temp_data.append(source_ip_index)
                #     source_ip_index += 1
                # else:
                #     temp_data.append(source_ip_dict.get(data['source_ip']))
                #
                # # Handle the Destination IP Address Feature
                # if data['destination_ip'] not in dest_ip_dict:
                #     dest_ip_dict.update({data['destination_ip']: dest_ip_index})
                #     temp_data.append(dest_ip_index)
                #     dest_ip_index += 1
                # else:
                #     temp_data.append(dest_ip_dict.get(data['destination_ip']))
                #
                # # Handle the Source Port Feature
                # if data['source_port'] not in source_port_dict:
                #     source_port_dict.update({data['source_port']: source_ip_index})
                #     temp_data.append(source_port_index)
                #     source_port_index += 1
                # else:
                #     temp_data.append(source_port_dict.get(data['source_port']))
                #
                # # Handle the Destination Port Feature
                # if data['destination_port'] not in dest_port_dict:
                #     dest_port_dict.update({data['destination_port']: dest_port_index})
                #     temp_data.append(dest_port_index)
                #     dest_port_index += 1
                # else:
                #     temp_data.append(dest_port_dict.get(data['destination_port']))

                # Handle the SSL/TLS Version Feature
                if data['version'] not in self.version_dict:
                    self.version_dict.update({data['version']: self.version_index})
                    temp_data.append(self.version_index)
                    self.version_index += 1
                else:
                    temp_data.append(self.version_dict.get(data['version']))

                # Handle the Selected Ciphersuite Feature
                if data['selected_ciphersuite'] not in self.cipher_dict:
                    self.cipher_dict.update({data['selected_ciphersuite']: self.cipher_index})
                    temp_data.append(self.cipher_index)
                    self.cipher_index += 1
                else:
                    temp_data.append(self.cipher_dict.get(data['selected_ciphersuite']))

                temp_data.append(0)
            except TypeError:
                continue
            self.data_set.append(temp_data)

        for data in self.malicious_data:
            try:
                temp_data = []
                if data['version'] not in self.version_dict:
                    self.version_dict.update({data['version']: self.version_index})
                    temp_data.append(self.version_index)
                    self.version_index += 1
                else:
                    temp_data.append(self.version_dict.get(data['version']))

                # Handle the Selected Ciphersuite Feature
                if data['selected_ciphersuite'] not in self.cipher_dict:
                    self.cipher_dict.update({data['selected_ciphersuite']: self.cipher_index})
                    temp_data.append(self.cipher_index)
                    self.cipher_index += 1
                else:
                    temp_data.append(self.cipher_dict.get(data['selected_ciphersuite']))

                temp_data.append(1)
            except TypeError:
                continue
            self.data_set.append(temp_data)

    def __standardize(self, data, mean=None, std=None):
        if mean is None and std is None:
            means = numpy.mean(data, axis=0)
            stds = numpy.std(data, axis=0)

            for i in range(len(data)):
                for j in range(len(data[i])):
                    data[i][j] = (data[i][j] - means[j]) / stds[j]

            return data, means, stds
            # return data, 0, 0
        else:
            for i in range(len(data)):
                for j in range(len(data[i])):
                    data[i][j] = (data[i][j] - mean[j]) / std[j]
            return data

    def generate_model(self):
        # Randomly mix up the data
        random.shuffle(self.data_set)
        # Take Approximately 2/3 to train with
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
        self.model = svm.SVC()
        self.model.fit(self.train_sample_x, self.train_sample_y)

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
        print(f'Accuracy: {accuracy*100:.2f}%')

    def test_model(self, json_data):
        if self.model is None:
            self.generate_model()
        loaded_json = json.loads(json_data)
        data = []
        for ele in loaded_json:
            try:
                temp = []
                if ele['version'] not in self.version_dict:
                    self.version_dict.update({ele['version']: self.version_index})
                    temp.append(self.version_index)
                    self.version_index += 1
                else:
                    temp.append(self.version_dict.get(ele['version']))

                if ele['selected_ciphersuite'] not in self.cipher_dict:
                    self.cipher_dict.update({ele['selected_ciphersuite']: self.cipher_index})
                    temp.append(self.cipher_index)
                    self.cipher_index += 1
                else:
                    temp.append(self.cipher_dict.get(ele['selected_ciphersuite']))
            except TypeError:
                continue
            data.append(temp)
        std_data = self.__standardize(data, self.train_means, self.train_std)
        pred_value = self.model.predict(std_data)

        for val in pred_value:
            if val == 0:
                print('Found Benign Data')
            else:
                print('Found Malicious Data')

        print(self.version_dict)
        print(self.cipher_dict)

    def show(self):
        ax = plt.axes(projection='3d')

        version = [row[0] for row in self.train_sample_x]
        cipher = [row[1] for row in self.train_sample_x]
        train, = ax.plot(cipher, version, self.train_sample_y, 'rx')

        version = [row[0] for row in self.test_sample_x]
        cipher = [row[1] for row in self.test_sample_x]
        test, = ax.plot(cipher, version, self.test_sample_y, 'bo')

        test.set_label('Testing Set')
        train.set_label('Training Set')
        plt.legend()

        ax.set_xlabel('Selected Cipher Suite')
        ax.set_ylabel('SSL/TLS Version')
        ax.set_zlabel('0 = Benign, 1 = Malicious')
        plt.title('Support Vector Machine')

        plt.show()


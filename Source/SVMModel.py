from Source.Abstract import TLSHelper
from Source.SQL.SqlHelper import SQL_Helper
from mlxtend.plotting import plot_decision_regions
from scipy import interp
from sklearn.svm import SVC
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import StratifiedKFold

import math
import matplotlib.pyplot as plt
import numpy

__author__ = "David Debreceni Jr"

class SVMModel:
    """
    Train and Implement a Support Vector Machine Model using features:
    TLS Version; Selected CipherSuite;
    """

    def __init__(self):
        self.sql_helper = SQL_Helper()
        self.benign_data = self.__load_data("benign_domains", 1000)
        self.malicious_data = self.__load_data("malicious_domains", 1000)
        self.data_set = []
        self.__extract_features(self.benign_data, 0)
        self.__extract_features(self.malicious_data, 1)

        self.model = SVC(kernel='poly')
        self.train_sample_x = None
        self.train_sample_y = None
        self.train_means = None
        self.train_std = None
        self.train_sample_x = None
        self.train_sample_y = None
        self.predicted = None

    def __load_data(self, table_name, num=None):
        try:
            if num:
                return self.sql_helper.read_x_from_table(table_name, num)
            else:
                return self.sql_helper.read_all_from_table(table_name)
        except Exception as error:
            print(f'{error}')
    
    def __extract_features(self, data, y_val):
        for x in data:
            temp = []
            try:
                if type(x['Version']) is str:
                    temp.append([key for key, value in TLSHelper.TLS_VERSIONS.items() if x['Version'] in value][0])
                else:
                    temp.append(x['Version'])
            except IndexError:
                temp.append(0)
            
            try:
                if type(x['CipherSuite']) is str:
                    temp.append([key for key, value in TLSHelper.CIPHERSUITES.items() if x['CipherSuite'] in value][0])
                else:
                    temp.append(x['CipherSuite'])
            except IndexError:
                temp.append(0)

            temp.append(y_val)
            self.data_set.append(temp)

    def train_model(self):
        X = numpy.c_[[row[:-1] for row in self.data_set]]
        y = numpy.c_[[row[-1] for row in self.data_set]]
        c,r = y.shape
        y = y.reshape(c,)

        cv = StratifiedKFold(n_splits=5)
        classifier = SVC(kernel='linear', probability=True, random_state=numpy.random.RandomState(0))

        tprs = []
        aucs = []
        mean_fpr = numpy.linspace(0, 1, len(X))

        i = 0
        for train, test in cv.split(X, y):
            probas_ = classifier.fit(X[train], y[train]).predict_proba(X[test])
            fpr, tpr, thresholds = roc_curve(y[test], probas_[:, 1])
            tprs.append(interp(mean_fpr, fpr, tpr))
            tprs[-1][0] = 0.0
            roc_auc = auc(fpr, tpr)
            aucs.append(roc_auc)
            plt.plot(fpr, tpr, lw=1, alpha=0.3, label='ROC fold %d (AUC = %0.2f)' % (i, roc_auc))
            i += 1
        plt.plot([0, 1], [0, 1], linestyle = '--', lw=2, color='r', label='Luck', alpha=0.8)
        mean_tpr = numpy.mean(tprs, axis=0)
        mean_tpr[-1] = 1.0
        mean_auc = auc(mean_fpr, mean_tpr)
        std_auc = numpy.std(aucs)
        plt.plot(mean_fpr, mean_tpr, color='b', label=r'Mean ROC (AUC = %0.2f $\pm$ %0.2f)' % (mean_auc, std_auc),
                 lw=2, alpha=0.8)

        std_tpr = numpy.std(tprs, axis=0)
        tprs_upper = numpy.minimum(mean_tpr + std_tpr, 1)
        tprs_lower = numpy.maximum(mean_tpr - std_tpr, 0)
        plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='grey', alpha=0.2, label=r'$\pm$ 1 std. dev.')
        plt.xlim([-0.05, 1.05])
        plt.ylim([-0.05, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC TLS Version & CipherSuite')
        plt.legend(loc="lower right")
        plt.show()

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

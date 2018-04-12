#!/usr/bin/python3

#pip install mysqlclient
import MySQLdb
import json

class SQL_Helper:
    def __init__(self, config_data):
        self.database = MySQLdb.connect(host = config_data['mysql']['host'],
                        port = int(config_data['mysql']['port']),
                        user = config_data['mysql']['user'],
                        passwd = config_data['mysql']['passwd'],
                        db = config_data['mysql']['db'])
        self.cursor = self.database.cursor();

    def close_db(self):
        self.database.close()
        self.cursor.close()

    #expects valid SQL query as a string
    def send_query(self, query):
        try:
            ret = self.cursor.execute(query)
        except Exception as err:
            print("Error:{}\n{} is invalid.\nPlease reevaluate your query".format(err, query))
            return None
        
        return ret

    #IGNORE THIS FOR NOW
    #expects table name as string and values in form of list
    #where values correspond to table columns.
    #Table: svm_data only has 2 columns: Version, Cipher
    def add_to_table(self, values, name):
        query = "INSERT INTO " + name + " VALUES ("
        for item in values:
            query = query + item + ", "
        query = query[:-2] + ")"
        self.send_query(query)
    
    #expects table name as string. returns all values from table entries as tuple of tuples.
    def read_all_from_table(self, name):
        query = "SELECT * FROM " + name
        ret = self.send_query(query)
        rows = self.cursor.fetchall()

        return rows

def read_config(config_file):
    with open(config_file) as json_data:
        data = json.load(json_data)
    return(data)


config_data = read_config('config.json')

foo = SQL_Helper(config_data)
sql_data = foo.read_all_from_table('svm_data')
print(sql_data)
foo.close_db()

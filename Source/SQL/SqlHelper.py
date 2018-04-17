import MySQLdb
import json

__author__ = "Dallas Foglia, David Debreceni Jr"

class SQL_Helper:


    def __init__(self, config_file='config.json'):
        self.config_data = self.__read_config(config_file)

        self.database = MySQLdb.connect(
            host = self.config_data['mysql']['host'],
            port = int(self.config_data['mysql']['port']),
            user = self.config_data['mysql']['user'],
            passwd = self.config_data['mysql']['passwd'],
            db = self.config_data['mysql']['db']
        )
        self.cursor = self.database.cursor()

    # Properties

    @property
    def __benign_and_malicious_columns(self):
        return [
        'Source_IP', 
        'Destination_IP', 
        'Source_Port', 
        'Destination_Port',
        'Version',
        'CipherSuite'
        ]
    
    # Private Methods

    def __read_config(self, config_file):
        try:
            with open(config_file) as json_data:
                return json.load(json_data)
        except Exception as error:
            print(f'{error}')

    # Public Methods

    def close_db(self):
        self.database.close()
        self.cursor.close()

    #expects valid SQL query as a string
    def send_query(self, query):
        try:
            ret = self.cursor.execute(query)
        except Exception as err:
            print("Error:{}\n{} is invalid.\nPlease re-evaluate your query".format(err, query))
            return None
        
        return ret

    #expects table name as string and columns for insertion in form of list
    #list entries must correspond to the following format:
    #[source_ip, destination_ip, source_port, destination_port, version, selected_ciphersuite]
    def add_to_table(self, values, name):
        query = "INSERT INTO " + name + " VALUES ("
        for item in values:
            query = query + item + ", "
        query = query[:-2] + ")"

        self.send_query(query)
        self.database.commit()
    
    #expects table name as string. returns all table entries in a dict of lists
    def read_all_from_table(self, name):
        query = "SELECT * FROM " + name
        ret = self.send_query(query)
        rows = self.cursor.fetchall()

        return [
            dict(
                zip(self.__benign_and_malicious_columns, rows[i])
            ) for i in range(len(rows))
        ]


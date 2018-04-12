README
======

ENTD, Encrypted Network Traffic Detector, is a Python 3 program for analyzing packet captures (pcaps) and distinguishing between benign and malicious traffic in the packet via port 443 (SSL/TLS).

Currently the features that are supported are as follows:
* Reading Packet Capture and Extracting the Server Hello Information
* Able to distinguish between Malicious and Benign Traffic

Usage
-----
You can use the program in Python 3 with

    ./main.py -f "path/to/packet/capture/file.pcap"
    
Example
-------

    ./main.py -f "Sample PCAPs/malicious_packet.pcap"

Requirements
------------
* Python 3.6.1 or newer
* dpkt via `pip install dpkt`
* mlxtend via `pip install mlxtend`
* scikit-learn via `pip install scikit-learn`
* mysqlclient via `pip install mysqlclient`

Issues
------
* Currently the SVM shows a hyperplane due to the ciphersuites.  Need more data to fill our feature space.
* Currently builds the SVM model every run through.
* There is a bug in dpkt with reading packets.  Therefore, I have hand constructed the JSON features from the malicious packet we have.

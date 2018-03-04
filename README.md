======
README
======

ENTAD, Encrypted Network Traffic Anomaly Detector, is a Python 3 program for analyzing packet captures (pcaps) and
detecting any anomalies in packet via port 443 (SSL/TLS).

Currently the features that are supported are as follows:
* Reading Packet Capture and Extracting the Server Hello Information

Usage
-----
You can use the program in Python 3 with

    ./main.py -f "path/to/packet/capture/file.pcap"

Requirements
------------
* Python 3.6.1 or newer
* dpkt via `pip install dpkt`

#!/usr/bin/env python3

from Source.ArgumentParser import ArgParser
from Source.ProcessPacket import ProcessPacket
import json

__author__ = "David Debreceni Jr"

def main():
    arg_parser = ArgParser()
    kwargs = arg_parser.parse_args()
    process_packet = ProcessPacket(kwargs['file'], kwargs['ports'])
    output = json.dumps(process_packet.get_server_hello_data())

    # For now we will write the json dumps to a file
    with open('JSON/server_hello_dump.json', 'w') as file:
        file.write(output)

if __name__ == "__main__":
    main()

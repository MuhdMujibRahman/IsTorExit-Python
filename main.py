#!/usr/bin/python
import pydig
from ipcalc import Network
import sys
import re
import getopt
import json


def is_tor_exit_ip(ip:str):
    print(f"Checking is TOR exit for {ip}")

    # The original IP address is reversed 
    reversed_ip = ".".join(ip.split('.')[::-1])

    # Run dig and use the reversed ip with dnes.torproject.org
    result = pydig.query(f'{reversed_ip}.dnsel.torproject.org', 'A')

    # Check if the result return 127.0.0.*
    if len(result) > 0 and  re.match(r'127.0.0.\d', result[0]) and result[0] != '127.0.0.1':
        print(f"* {ip=} is tor exit ip")
        return True
    else:
        print(f"* {ip=} is not tor exit ip")
        return False

def get_to_ip_range(ip:str):
    print("*Getting ip ranges ...")
    # Define the prefix to set ip ranges
    prefix = netwkPrefix
    localnet = Network(f'{ip}/{prefix}')
    ip_range = f'{localnet.network()}/{prefix}'
    return ip_range

def apply_to_tf(ip:str):
    with open (jsonFilePath, 'r') as json_file:
        json_data = json.load(json_file)    
    
    # Get the current ip list
    current_expressions = json_data['variable']['tor_exit_ip_list']['default']
    ip_list_range = expressions_to_list(current_expressions) 

    # Check if ip in list before update
    new_expressions = list_of_expression(ip_list_range, ip)
    if new_expressions is False:
        return '* No update'

    json_data['variable']['tor_exit_ip_list']['default'] = new_expressions

    with open(jsonFilePath, 'w') as json_file:
        json_file.write(json.dumps(json_data, indent=4))
        print(f" File have been updated")


if __name__ == "__main__":
    # list of command line arguments
    argumentList = sys.argv[1:]

    ip = None
    netwkPrefix = None
    jsonFilePath = None

    # Options
    options = "h:i:f:p"

    # Long options
    long_options = ["Help", "ipAddress", "jsonFile", "netPrefix"]

    try:
        arguments, values = getopt.getopt(argumentList, options, long_options)

        for currentArgument, currentValue, in arguments:
            if currentValue in ("-h", "--Help"):
                print("Displaying Help")
            elif currentValue in ("-i", "--ipAddress"):
                ip = currentValue
            elif currentValue in ("-f", "--jsonFilePath"):
                jsonFilePath = currentValue
    except getopt.error as err:
        print(str(err))

    
    if ip != None and netwkPrefix != None:
        is_tor_exit_ip(ip)
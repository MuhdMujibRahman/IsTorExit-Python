#!/usr/bin/python
import pydig
from ipcalc import Network
import sys

def is_tor_exit_ip(ip:str):
    reversed_ip = ".".join(ip.split('.')[::-1])
    result = pydig.query(f'{reversed_ip}.dnsel.torproject.org', 'A')
    
    if result.count() > 0 and  result[0] == '127.0.0.2':
        return True
    else:
        return False

def get_to_ip_range(ip:str):
    prefix = '28'
    localnet = Network(f'{ip}/{prefix}')
    ip_range = f'{localnet.network()}/{prefix}'
    return ip_range

if __name__ == "__main__":
    ip = sys.argv
    if is_tor_exit_ip(ip):
        get_to_ip_range(ip)

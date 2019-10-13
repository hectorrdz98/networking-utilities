import scapy.all as scapy
import sqlite3
from sqlite3 import Error

conn = sqlite3.connect('ieee.db')
c = conn.cursor()

import socket

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        print(s.getsockname())
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_organization(mac):
    c.execute("SELECT * FROM ieee WHERE mac=?", (mac,))
    conn.commit()
    return c.fetchone()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]
    clients_list = []
    for element in answered_list:
        fixedMAC = '-'.join(element[1].hwsrc.split(':')[0:3]).upper()
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'enterprise': get_organization(fixedMAC)[1]}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print('IP\t\t\tMAC Address\t\t\tEnterprise')
    print('---------------------------------------------------------------------------------------')
    for client in results_list:
        print(client['ip'] + "\t\t" + client['mac'] + "\t\t" + client['enterprise'])

ipFormat = '{}.1/24'.format('.'.join(get_ip().split('.')[0:3]))

scan_result = scan(ipFormat)
print_result(scan_result)
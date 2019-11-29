from flask import Flask
from flask import render_template
from flask import request
from flask import json, Response
import scapy.all as scapy
import sqlite3
from sqlite3 import Error
import socket
import os
import re

app = Flask(__name__)
get_bin = lambda x: format(x, 'b')

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_mac():
    data = os.popen('ipconfig /all').read()
    things = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data)
    mac = ''
    ip = get_ip()
    for i in range(len(things)):
        if things[i] == ip: mac = things[i+1]
    return mac

def get_organization(mac):
    with sqlite3.connect('ieee.db') as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM ieee WHERE mac=?", (mac,))
        conn.commit()
        return c.fetchone()

def scan(ip):
    #arp_request = scapy.ARP(pdst=ip)
    #broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    #arp_request_broadcast = broadcast/arp_request
    #answered_list = scapy.srp(arp_request_broadcast, timeout=1,
    
    answered_list = scapy.arping(ip, timeout=1,
                              verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        fixedMAC = '-'.join(element[1].hwsrc.split(':')[0:3]).upper()
        org = get_organization(fixedMAC)
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'enterprise': org[1] if org else ''}
        clients_list.append(client_dict)
    return clients_list

def getAddresses(ip, mac):
    networkParts = getNetworkAddress(ip, mac)
    ipFormat = str(networkParts[0]) + '/' + str(networkParts[1])
    print("Get all IP from:", ipFormat)
    scan_result = scan(ipFormat)
    return { 'network': networkParts[0], 'networkSize': networkParts[1], 'scan_result': scan_result }

def getNetworkAddress(ip, mac):
    ipParts = ip.split('.')
    macParts = mac.split('.')

    binIp = ''
    binMac = ''
    binNetwork = ''

    networkSize = len(re.findall(r'1', mac))

    for i in range(len(ipParts)):
        preBinIp = get_bin(int(ipParts[i]))
        for n in range(8-len(preBinIp)): binIp += '0'
        binIp += preBinIp
        
        preBinMac = get_bin(int(macParts[i]))
        for n in range(8-len(preBinMac)): binMac += '0'
        binMac += preBinMac
        
        if i < len(ipParts) - 1:
            binIp += '.'
            binMac += '.'
    
    for i in range(len(binIp)):
        if binMac[i] == '.': binNetwork += '.'
        elif binMac[i] == '1': 
            binNetwork += binIp[i]
            networkSize += 1
        else: binNetwork += '0'
    
    networkParts = binNetwork.split('.')
    network = ''

    for i in range(len(networkParts)):
        network += str(int(networkParts[i], 2))
        if i < len(networkParts) - 1: network += '.'
    
    return [network, networkSize]

@app.route("/")
def index():
    return render_template('index.html')

@app.route('/networkScanner', methods=['GET', 'POST'])
def networkScanner():
    ip=get_ip()
    mac=get_mac()
    if request.method == 'POST':
        datas = getAddresses(ip, mac)
        json_string = json.dumps(datas['scan_result'], ensure_ascii = False)
        response = Response(json_string,content_type="application/json; charset=utf-8" )
        return response
    else:
        datas = getAddresses(ip, mac)
        return render_template('addressesList.html', datas=datas['scan_result'], 
            ip=ip, mac=mac, network=datas['network'], netSize=datas['networkSize'])

@app.route('/networkHost', methods=['GET', 'POST'])
def networkHost():
    if request.method == 'POST':
        pass
    else:
        ip = get_ip()
        mac=get_mac()
        return render_template('networkHost.html', ip=ip, mac=mac)

@app.route('/subnetting', methods=['GET', 'POST'])
def subnetting():
    if request.method == 'POST':
        pass
    else:
        return render_template('subnetting.html')

if __name__ == "__main__":
    app.run(host='localhost', port=7711, debug=True)
from flask import Flask
from flask import render_template
from flask import request
from flask import json, Response
import scapy.all as scapy
import sqlite3
from sqlite3 import Error
import socket

app = Flask(__name__)

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
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'enterprise': get_organization(fixedMAC)[1]}
        clients_list.append(client_dict)
    return clients_list

def getAddresses():
    ipFormat = '{}.1/24'.format('.'.join(get_ip().split('.')[0:3]))
    scan_result = scan(ipFormat)
    return scan_result

@app.route("/")
def index():
    return render_template('index.html')

@app.route('/networkScanner', methods=['GET', 'POST'])
def networkScanner():
    if request.method == 'POST':
        json_string = json.dumps(getAddresses(), ensure_ascii = False)
        response = Response(json_string,content_type="application/json; charset=utf-8" )
        return response
    else:
        datas = getAddresses()
        return render_template('addressesList.html', datas=datas, ip=get_ip())

if __name__ == "__main__":
    app.run(host='localhost', port=7711, debug=True)
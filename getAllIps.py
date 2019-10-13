from scapy.all import *
import sqlite3
from sqlite3 import Error

conn = sqlite3.connect('ieee.db')
c = conn.cursor()

def get_organization(mac):
    c.execute("SELECT * FROM ieee WHERE mac=?", (mac,))
    conn.commit()
    return c.fetchone()

TIMEOUT = 2

available = []
unavailable = []

for n in range(1, 256):
    packet = IP(src="172.16.9.216", dst="172.16.8.{}".format(n))/ICMP()/"hi"
    reply = sr1(packet, inter=0.5, timeout=1)
    if not (reply is None):
        print(reply.src, "is online")
        ans,unans = arping(reply.src, verbose=0)
        mac = None
        for s,r in ans:
            mac = r[Ether].src
        available.append([reply.src, mac])
    else:
        print("Timeout waiting for %s" % packet[IP].dst)
        unavailable.append(packet[IP].dst)


print()
print()
print('--- Final results ---')
print('Available: {}'.format(len(available)))
print('Unavailable: {}'.format(len(unavailable)))
print('---------------------')
print()
for ava in available:
    fixedMAC = '-'.join(ava[1].split(':')[0:3]).upper() if ava[1] else None
    organization = get_organization(fixedMAC)[1] if fixedMAC else ''
    print('{} {} {}'.format(ava[0], ava[1], organization))
    
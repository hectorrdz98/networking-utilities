from scapy.all import *

TIMEOUT = 2

"""
packet = IP(dst="172.16.9.215")/ICMP()
reply = send(packet, iface="Ethernet", return_packets=True)
print(reply)
"""


packet = IP(src="192.168.100.23", dst="192.168.100.23")/ICMP()/"hi"
#reply = sr1(IP(dst="www.cisco.com")/ICMP()/"XXXXXXXXXXX", inter=0.5, retry=-2, timeout=1)
reply = sr1(packet, inter=0.5, retry=-2, timeout=1)
if not (reply is None):
    print(reply.dst, "is online")
    # reply.show()
    ans,unans = arping("192.168.100.23", verbose=0)
    for s,r in ans:
        print(r[Ether].src)
else:
    print("Timeout waiting for %s" % packet[IP].dst)


"""
packet = IP(dst="www.google.com")/ICMP()/"hi"
reply = send(packet, iface="Wi-Fi", return_packets=True)
"""
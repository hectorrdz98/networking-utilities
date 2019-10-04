from scapy.all import *

TIMEOUT = 2

available = []
unavailable = []

for n in range(1, 255):
    packet = IP(src="172.16.26.75", dst="172.16.26.{}".format(n))/ICMP()/"hi"
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
    print('{} -> {}'.format(ava[0], ava[1]))
from scapy.all import sendpfast
from scapy.all import *

# 创建数据包
#  = IP(src="192.168.0.1", dst="192.168.0.2") / TCP(sport=1234, dport=80)
#  = IP(src="192.168.0.2", dst="192.168.0.1") / TCP(sport=80, dport=1234)

packet1 =  Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=2312, dport=80)
packet2 = Ether(src='00:00:00:00:00:03', dst='00:00:00:00:00:04')/IP(src='10.0.0.2', dst='10.0.0.3')/UDP(sport=1111, dport=2222)
for i in range(500):
    sendp(packet1, iface="s1-eth1")
    time.sleep(0.005)
for i in range(500):
    sendp(packet2, iface="s1-eth2")
    time.sleep(0.005)
print("success!")
# 将数据包写入文件
wrpcap("packet.pcap", [packet1, packet2])
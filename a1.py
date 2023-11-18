from collections import Counter
from scapy.all import rdpcap

def calculate_flow_frequency(dataset):
    flow_counter = Counter()
    for packet in dataset:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            src_port = packet[""].sport
            dst_port = packet[""].dport
            proto = packet["IP"].proto
            flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
            flow_counter[flow_key] += 1
    return flow_counter

pcap_file = "sdn_2.pcap"
dataset = rdpcap(pcap_file)
flow_frequency = calculate_flow_frequency(dataset)

for flow, freq in flow_frequency.items():
    src_ip, dst_ip, src_port, dst_port, proto = flow
    print(f"源IP: {src_ip}, 目的IP: {dst_ip}, 源端口: {src_port}, 目的端口: {dst_port}, 协议: {proto}, 频率: {freq} 次")



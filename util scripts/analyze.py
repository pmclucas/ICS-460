from scapy.all import rdpcap, IP, TCP, ICMP
import sys
import matplotlib.pyplot as plt
from collections import defaultdict

# Grab pcap file from command line
if len(sys.argv) < 2:
    print("Usage: python3 analyze.py <capture.pcap>")
    sys.exit()

pcap_file = sys.argv[1]
packets = rdpcap(pcap_file)

# Pieces for charts
src_ip_counts = defaultdict(int)
timestamps = []
blocked = 0
allowed = 0

# Loop through every packet and collect data
for packet in packets:
    if not packet.haslayer(IP):
        continue

    
    # Chart 1 - top source IPs
    
    


    # Chart 2 - timestamps

    # Chart 3 - blocked vs allowed


# Generate charts
# Chart 1 - Top source IPs
def plot_top_ips():
    pass

# Chart 2 - Packets over time
def plot_packets_over_time():
    pass

# Chart 3 - Blocked vs allowed
def plot_blocked_allowed():
    pass

plot_top_ips()
plot_packets_over_time()
plot_blocked_allowed()
plt.show()
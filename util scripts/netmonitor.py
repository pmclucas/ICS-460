from scapy.all import sniff,IP,TCP,ICMP
import sys
from collections import defaultdict
import time
import logging
import subprocess

#Threshholds for attack

SYN_THRESHOLD = 100 #pkt
ICMP_THRESHOLD = 100  #pkt
WINDOW = 1 #s

#VLAN Variables

VLAN10 = "10.10.10"
VLAN20 = "20.20.20"

_Locked_Down = False

#If wiithin 1s we get either a SYN burst or ICMP burst of 100 packets or greater
#Do something to harden our network

#Logging setup
#Saving data into monitor.log file within our util scripts folder
#Everything from this file will be sent there, please access that file
#To view the current logging of the network
logging.basicConfig(filename='/util scripts/Log Data/monitor.log', level=logging.INFO)


#Actual packet counters
_syn_count = defaultdict(int)
_icmp_count = defaultdict(int)
_window_start = time.time()

#Repeated commands
tbl = ["sudo", "nft", "-f"]

#Network swapping function

def __apply_hardened():
    subprocess.run(tbl + ["/etc/nftables/nftables-hardened.conf"])
    #Marking the time when the ruleset changed
    with open ("/util scripts/Log Data/time_of_attk.txt", "w") as fw:
        fw.write(str(time.time()));
    return

def __apply_open():
    subprocess.run(tbl + ["/etc/nftables/nftables-open.conf"])
    return

def __check_thresh(srcIP):
    global _window_start, _syn_count, _icmp_count,_Locked_Down

    #Checking if admin hit reset for open policies

    currentTime = time.time()

    if currentTime - _window_start >= WINDOW:
        _syn_count.clear()
        _icmp_count.clear()
        _window_start = currentTime

    else:

        if(_syn_count[srcIP] >= SYN_THRESHOLD or _icmp_count[srcIP] >= ICMP_THRESHOLD):
            #Logging the attack
            logging.warning(f"Attack detected! From {srcIP} - SYN Count: {_syn_count[srcIP]}")

            if(_Locked_Down == False):
                __apply_hardened()
                logging.warning("Hardened ruleset now applied!")
                _Locked_Down = True



def _process_pkt(packet):
    
    if not packet.haslayer(IP):
        return
    

    global _syn_count, _icmp_count,_Locked_Down
    srcIP = packet[IP].src
    
    if(packet.haslayer(TCP) and packet[TCP].flags == 'S'):
        _syn_count[srcIP] += 1

    if(packet.haslayer(ICMP)):
        _icmp_count[srcIP] +=1

    __check_thresh(srcIP)


#Main Loop, repeating a sniff until we hit a need to harden
if len(sys.argv) > 1 and sys.argv[1] == "reset":
    __apply_open()
    logging.warning("Open ruleset now applied!")
    sys.exit()
sniff(iface="eth0", promisc = True, store = False, prn=_process_pkt)
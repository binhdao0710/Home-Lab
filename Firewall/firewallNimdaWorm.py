import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

THRESHOLD = 40
print(f"THRESHOLD:{THRESHOLD}")

def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)
#read files and closes them immediately afterward
#get rid of white space in each line
#return ips as a set to avoid duplicates

def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

def log_event(message):
    log_folder="logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%D, %H-%M-%S")
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")

    with open (log_file, "a") as file: 
        file.write(f"{message}\n")

#log_file changes path everytime a log_event happen
#at the end of the function, new message is aded to the new txt file

def packet_callback(packet):
    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return
    
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP") 
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return 
    
    if is_nimda_worm(packet):
        os.system(f"Blockign Nimda source IP: {src_ip}")
        log_event(f"Blocking Nimda source IP:{src_ip}")
        return 
    
    packet_count[src_ip]+= 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >=1:
        for ip, count in packet_count.items():
            packet_rate = count/time_interval

        if packet_rate > THRESHOLD and ip not in blocked_ips:
            print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
            os.system(f"iptables -A INPUT -s {ip} -j DROP")
            log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
            blocked_ips.add(ip)

    packet_count.clear()
    start_time[0] = current_time

    if __name__ == "__main__":
        if os.getuid() != 0:
            print("This script requires root priviledges")
            sys.exit(1)

    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips= read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)

        
from scapy.all import DNS, IP, UDP, DNSQR, DNSRROPT, send
import random
import threading
import time
import pandas as pd

DNS_SERVER_IP = "127.0.0.1"
DNS_SERVER_PORT = 53
IFACE = "lo"

# malicious domains from CSV
csv_path = "/home/avii09/Desktop/dns_firewall/dns-firewall/data/mal_dom.csv"
df = pd.read_csv(csv_path)
BLACKLISTED_DOMAINS = df["Domain"].dropna().tolist()

# benign domains from CSV
csv_path = "/home/avii09/Desktop/dns_firewall/dns-firewall/data/leg_domain.csv"
df = pd.read_csv(csv_path)
LEGITIMATE_DOMAINS = df["Domain"].dropna().tolist()

#LEGITIMATE_DOMAINS = ["example.com", "openai.com", "github.com"]
#BLACKLISTED_DOMAINS = ["badsite.com", "malware.xyz"]
TOTAL_UNIQUE_IPS = 5
MIN_QUERIES = 1
MAX_QUERIES = 20
QUERY_INTERVAL = 0.5
QUERY_TYPES = [1, 2, 15, 16, 28] # A, NS, MX, TXT, AAAA

# store summaries here
ip_summaries = []

def generate_random_ip(is_legit=True):
    if is_legit:
        first_octet = random.choice([10, 192, 172])
        if first_octet == 10:
            return f"10.0.0.{random.randint(1, 9)}"
        elif first_octet == 172:
            return f"172.{random.randint(16, 31)}.{random.randint(0, 9)}.{random.randint(1, 9)}"
        else:
            return f"192.168.{random.randint(0, 9)}.{random.randint(0, 9)}"
    else:
        first_octet = random.choice([45, 89, 91, 185, 203, 222])
        return f"{first_octet}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def send_dns_query(domain, spoof_ip, is_legit):
    qtype = random.choice(QUERY_TYPES)
    ip_layer = IP(dst=DNS_SERVER_IP, src=spoof_ip)
    udp_layer = UDP(dport=DNS_SERVER_PORT, sport=random.randint(1024, 65535))
    dns_layer = DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype), ar=DNSRROPT(rclass=4096))
    pkt = ip_layer / udp_layer / dns_layer
    send(pkt, iface=IFACE, verbose=0)
    
    print(f"[SEND] Domain = {domain}, IP = {spoof_ip}, Qtype = {qtype}, Qname = {dns_layer.qd.qname}, [{'legitimate' if is_legit else 'malicious'}]")

def simulate_ip_traffic(ip_address, is_legit):
    domain_list = LEGITIMATE_DOMAINS if is_legit else BLACKLISTED_DOMAINS
    num_queries = random.randint(MIN_QUERIES, MAX_QUERIES)

    for _ in range(num_queries):
        domain = random.choice(domain_list)
        if not is_legit:
            domain = f"{domain}"
        
        send_dns_query(domain, spoof_ip=ip_address, is_legit=is_legit)
        time.sleep(QUERY_INTERVAL)

    
    summary_message = f"[+] IP {ip_address} ({'legitimate' if is_legit else 'malicious'}) sent {num_queries} queries."
    ip_summaries.append(summary_message)

def launch_attack():
    threads = []

    print("[*] Starting DNS traffic simulation...")
    for _ in range(TOTAL_UNIQUE_IPS):
        is_legit = random.choice([True, False])
        ip_address = generate_random_ip(is_legit)
        thread = threading.Thread(target=simulate_ip_traffic, args=(ip_address, is_legit))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    
    print()
    for summary in ip_summaries:
        print(summary)
    
    print("\n[*] Simulation complete.")

if __name__ == "__main__":
    launch_attack()

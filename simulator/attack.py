from scapy.all import DNS, IP, UDP, DNSQR, DNSRROPT, send
import random
import threading
import time

DNS_SERVER_IP = "127.0.0.1"
DNS_SERVER_PORT = 53
IFACE = "lo"  

# configure parameters
LEGITIMATE_DOMAINS = ["example.com", "openai.com", "github.com"]
BLACKLISTED_DOMAINS = ["badsite.com", "malware.xyz"]
LEGIT_QUERY_RATE = 1       # per second
MALICIOUS_QUERY_RATE = 1 # per second
ATTACK_DURATION = 2       # seconds
QUERY_TYPES = [1, 2, 15, 16, 28]  # A, NS, MX, TXT, AAAA


# ips like 185.220.100.240, 192.42.116.198, and 72.217.36.105
def generate_mal_ip():
    suspicious_first_octets = [45, 89, 91, 185, 203, 222]  
    first_octet = random.choice(suspicious_first_octets)

    second_octet = random.randint(0, 255)
    third_octet = random.randint(0, 255)
    fourth_octet = random.randint(1, 254)  

    return f"{first_octet}.{second_octet}.{third_octet}.{fourth_octet}"


def send_dns_query(domain, spoof_ip=None):
    qtype = random.choice(QUERY_TYPES)
    ip_layer = IP(dst=DNS_SERVER_IP)
    if spoof_ip:
        ip_layer.src = spoof_ip
    udp_layer = UDP(dport=DNS_SERVER_PORT, sport=random.randint(1024, 65535))
    dns_layer = DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype), ar=DNSRROPT(rclass=4096))
    pkt = ip_layer / udp_layer / dns_layer
    print(f"[SEND] DNS Query: Domain = {domain}, IP = {ip_layer.src}, Qtype = {dns_layer.qd.qtype}, Qname = {dns_layer.qd.qname}")
    # pkt.show()
    send(pkt, iface=IFACE, verbose=1)

# ips like 192.168.0.1, 10.0.0.1, 172.16.0.1 
def generate_legit_ip():
    first_octet = random.choice([10, 192, 172])  
    if first_octet == 10:
        return f"10.0.0.{random.randint(1, 9)}"
    elif first_octet == 172:
        second_octet = random.randint(16, 31)
        return f"172.{second_octet}.{random.randint(0, 9)}.{random.randint(1, 9)}"
    else:
        return f"192.168.{random.randint(0, 9)}.{random.randint(0, 9)}"

def simulate_legitimate_traffic():
    end_time = time.time() + ATTACK_DURATION
    while time.time() < end_time:
        domain = random.choice(LEGITIMATE_DOMAINS)
        spoof_ip = generate_legit_ip()
        send_dns_query(domain, spoof_ip=spoof_ip)
        time.sleep(1.0 / LEGIT_QUERY_RATE)

def simulate_malicious_flood():
    end_time = time.time() + ATTACK_DURATION
    while time.time() < end_time:
        domain = f"{random.randint(1,99999)}.{random.choice(BLACKLISTED_DOMAINS)}"
        spoof_ip = generate_mal_ip()
        send_dns_query(domain, spoof_ip=spoof_ip)
        time.sleep(1.0 / MALICIOUS_QUERY_RATE)

def launch_attack():
    legit_thread = threading.Thread(target=simulate_legitimate_traffic)
    malicious_thread = threading.Thread(target=simulate_malicious_flood)

    print("[*] Starting DNS traffic simulation...")
    legit_thread.start()
    malicious_thread.start()

    legit_thread.join()
    malicious_thread.join()
    print("[*] Simulation complete.")

if __name__ == "__main__":
    launch_attack()

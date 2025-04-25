from scapy.all import DNS, IP, UDP, DNSQR, send
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

def generate_spoofed_ip():
    first_octet = random.choice([10, 192, 172])  
    return f"{first_octet}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def send_dns_query(domain, spoof_ip=None):
    ip_layer = IP(dst=DNS_SERVER_IP)
    if spoof_ip:
        ip_layer.src = spoof_ip
    udp_layer = UDP(dport=DNS_SERVER_PORT, sport=random.randint(1024, 65535))
    dns_layer = DNS(rd=1, qd=DNSQR(qname=domain))
    pkt = ip_layer / udp_layer / dns_layer
    print(f"[SEND] DNS Query: Domain = {domain}, IP = {ip_layer.src}")
    # pkt.show()
    send(pkt, iface=IFACE, verbose=1)


def simulate_legitimate_traffic():
    end_time = time.time() + ATTACK_DURATION
    while time.time() < end_time:
        domain = random.choice(LEGITIMATE_DOMAINS)
        send_dns_query(domain)
        time.sleep(1.0 / LEGIT_QUERY_RATE)

def simulate_malicious_flood():
    end_time = time.time() + ATTACK_DURATION
    while time.time() < end_time:
        domain = f"{random.randint(1,99999)}.{random.choice(BLACKLISTED_DOMAINS)}"
        spoof_ip = generate_spoofed_ip()
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

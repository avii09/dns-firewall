# simulator/raw_attack.py

from query import launch_attack
import time

def main():
    print("[*] Launching raw DNS attack without any firewall measures...")
    launch_attack()
    time.sleep(10)
    print("[*] Raw attack complete. Log saved to logs/dns_query_log.csv")

if __name__ == "__main__":
    main()

# simulator/raw_attack.py

import sys
import os

# Add the simulator directory to the path to ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from query import launch_attack
import time

def main():
    print("[*] Launching raw DNS attack without any firewall measures...")
    launch_attack()
    time.sleep(10)
    print("[*] Raw attack complete. Log saved to logs/dns_query_log.csv")

if __name__ == "__main__":
    main()

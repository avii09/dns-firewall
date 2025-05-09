import pandas as pd
import subprocess
import time


def drop_matched_ips():
    # load matched domains and IPs
    matched_df = pd.read_csv("/mnt/97gb/projects/dns-firewall/logs/yara_matched.csv")
    malicious_ips = matched_df["ip"].dropna().unique()

    # load rate limiter logs
    logs_df = pd.read_csv("/mnt/97gb/projects/dns-firewall/logs/rate_limiter_logs.csv")

    # filter only the rows where IP is in malicious list
    to_block_df = logs_df[logs_df["IP"].isin(malicious_ips)]
    to_block_df.to_csv("/mnt/97gb/projects/dns-firewall/logs/to_block.csv", index=False)

    # filter rows that were NOT blocked
    not_blocked_df = logs_df[~logs_df["IP"].isin(malicious_ips)]
    not_blocked_df = not_blocked_df[["Timestamp", "Domain", "IP"]]
    not_blocked_df.to_csv("/mnt/97gb/projects/dns-firewall/logs/not_blocked.csv", index=False)

    
    for ip in malicious_ips:
        try:
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            print(f"[*] Dropped traffic from {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to block {ip}: {e}")

    print("[*] Blocking complete. Logs saved to to_block.csv and not_blocked.csv")


# if __name__ == "__main__":
#     time.sleep(1)

# try:
#     drop_matched_ips()
#     # result = subprocess.run(["python3", "/mnt/97gb/projects/dns-firewall/simulator/filter.py"], check=True)
# except subprocess.CalledProcessError as e:
#     print(f"[ERROR] rate_limiter.py failed with exit code {e.returncode}")
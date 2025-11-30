import pandas as pd
import yara
import os
import time
import subprocess


def rules_match():
    # Get project root directory (parent of simulator/)
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    logs_df = pd.read_csv(os.path.join(PROJECT_ROOT, "logs", "rate_limiter_logs.csv"))

    # Filter only rows where STATUS == 'OK'
    filtered_df = logs_df[logs_df["Status"] == "OK"].dropna(subset=["Domain", "IP"])
    # print(filtered_df)

    
    rules_path = os.path.join(PROJECT_ROOT, "YARA_RULES", "rules.yara")
    rules = yara.compile(filepath=rules_path)

    
    matches = []

    for _, row in filtered_df.iterrows():
        domain = row["Domain"]
        ip = row["IP"]
        timestampp = row["Timestamp"]

        try:
            result = rules.match(data=domain)
            if result:
                matches.append({
                    "domain": domain,
                    "ip": ip,
                    "rules": [r.rule for r in result],
                    "timestamp": timestampp
                })
        except Exception as e:
            print(f"Error scanning {domain}: {e}")

    
    output_df = pd.DataFrame(matches)
    output_path = os.path.join(PROJECT_ROOT, "logs", "yara_matched.csv")
    output_df.to_csv(output_path, index=False)

    print("[*] Rule matching complete. Logs saved to logs/yara_matched.csv.")





# if __name__ == "__main__":
#     time.sleep(1)

# try:
#     rules_match()
#     # result = subprocess.run(["python3", "/mnt/97gb/projects/dns-firewall/simulator/filter.py"], check=True)
# except subprocess.CalledProcessError as e:
#     print(f"[ERROR] rate_limiter.py failed with exit code {e.returncode}")
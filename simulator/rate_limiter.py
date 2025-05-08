import pandas as pd
from collections import defaultdict, deque
import time
from datetime import datetime

# Load the DNS query log
log_file = "/home/bhav/newfirewall/dns-firewall/simulator/dns_query_log.csv"

df = pd.read_csv(log_file)

df["Timestamp"] = pd.to_datetime(df["Timestamp"])
df["Timestamp"] = df["Timestamp"].astype("int64") / 1e9  # Convert nanoseconds to seconds (float)

df = df.sort_values(by="Timestamp")

# Sliding window settings
WINDOW_SIZE = 10  # seconds
THRESHOLD = 10  # max queries allowed in the window

# IP-specific request logs
ip_request_logs = defaultdict(deque)

#store output logs
output_logs = []

# Iterate through log entries
for _, row in df.iterrows():
    ip = row["Spoofed_IP"]
    timestamp = row["Timestamp"]
    domain = row["Domain"]
    category = row["Category"]

    # Clean up old timestamps outside the sliding window
    while ip_request_logs[ip] and timestamp - ip_request_logs[ip][0] > WINDOW_SIZE:
        ip_request_logs[ip].popleft()

    current_count = len(ip_request_logs[ip])

    if current_count < THRESHOLD:
        ip_request_logs[ip].append(timestamp)
        status = "OK"
    else:
        status = "DROP"
          # Save log entry
    output_logs.append({
        "Status": status,
        "IP": ip,
        "Domain": domain,
        "Timestamp": timestamp,
        "Current_Count": current_count + 1 if status == "OK" else current_count,
        "Threshold": THRESHOLD
    })
# Create DataFrame and write to CSV
output_df = pd.DataFrame(output_logs)
output_df.to_csv("rate_limiter_logs.csv", index=False)

print("[*] Sliding window rate limiting complete. Logs saved to rate_limiter_logs.csv.")




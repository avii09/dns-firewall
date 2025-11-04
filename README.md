# DNS Firewall and Attack Simulator

A small toolkit to simulate DNS traffic (including malicious bursts), apply a basic firewalling pipeline (rate-limiting + YARA-based filtering + iptables drop), and visualize results in a Streamlit dashboard.

## Features
- Raw DNS traffic generator using Scapy
- Sliding-window rate limiter over DNS queries
- YARA rule matching for domain-based detection
- Automatic `iptables` blocking for matched malicious IPs
- Streamlit dashboard with:
  - Attack launcher and live log views
  - Firewall run + results (logs, metrics, visualizations)
  - Comparative analysis (before vs after filtering)

## Project Structure
```text
dns-firewall/
  dashboard/
    app.py                     # Streamlit entrypoint with tabs
    attack.py                  # Launch raw attack and visualize traffic
    firewall.py                # Run firewall pipeline and visualize outputs
    comparative_analysis.py    # Before/After charts and key metrics
  simulator/
    main.py                    # Orchestrates full pipeline (attack → rate limit → YARA → drop)
    raw_attack.py              # Launches only the raw attack
    query.py                   # Generates DNS queries (benign and malicious)
    rate_limiter.py            # Sliding window rate limiter (logs decisions)
    filter.py                  # YARA match over domains
    drop_ip.py                 # Applies iptables drops, emits to_block/not_blocked
  data/
    leg_domain.csv             # Benign/legitimate domains
    mal_dom.csv                # Malicious/blacklisted domains
  YARA_RULES/
    rules.yara                 # YARA signatures for malicious domains
  requirements.txt
  LICENSE
  README.md
```

## Important Paths and Environment Assumptions
Several scripts reference absolute Linux paths for logs and data (e.g. `/mnt/97gb/projects/dns-firewall/...`). Adjust these to match your environment:

- Logs directory (expected by dashboard and simulator):
  - `/mnt/97gb/projects/dns-firewall/logs/`
  - Files produced/consumed:
    - `dns_query_log.csv` (from `simulator/query.py`)
    - `rate_limiter_logs.csv` (from `simulator/rate_limiter.py`)
    - `yara_matched.csv` (from `simulator/filter.py`)
    - `to_block.csv`, `not_blocked.csv` (from `simulator/drop_ip.py`)
- Data directory:
  - `/mnt/97gb/projects/dns-firewall/data/leg_domain.csv`
  - `/mnt/97gb/projects/dns-firewall/data/mal_dom.csv`
- YARA rules:
  - `/mnt/97gb/projects/dns-firewall/YARA_RULES/rules.yara`

If you are running on Windows or a different Linux path, search the repo for `/mnt/97gb/projects/dns-firewall` and update to a suitable location. Ensure the `logs/` directory exists.

## Prerequisites
- Python 3.8+
- `sudo` access (required for Scapy raw packets and `iptables`)
- Linux is recommended for `iptables` compatibility

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\\Scripts\\activate
pip install -r requirements.txt

# Create logs directory expected by the pipeline
mkdir -p /mnt/97gb/projects/dns-firewall/logs
```

If you are not using the default absolute path, create your own logs directory and update the hard-coded paths inside:
- `simulator/query.py`
- `simulator/rate_limiter.py`
- `simulator/filter.py`
- `simulator/drop_ip.py`
- `dashboard/attack.py`, `dashboard/firewall.py`, `dashboard/comparative_analysis.py`

## Quick Start

### 1) Run the Full Firewall Pipeline (CLI)
Runs: simulate traffic → rate limit → YARA match → block with iptables → write logs
```bash
sudo python3 simulator/main.py
```

### 2) Launch Only a Raw Attack (no firewall)
```bash
sudo python3 simulator/raw_attack.py
```

### 3) Start the Streamlit Dashboard
The dashboard gives you three tabs: Attack, Firewall, Comparative Analysis.
```bash
streamlit run dashboard/app.py
```

## Usage Details
- `simulator/main.py`
  - Calls `launch_attack()` to generate mixed benign/malicious DNS queries
  - Runs `rate_limit()` to produce `rate_limiter_logs.csv`
  - Runs `rules_match()` to produce `yara_matched.csv`
  - Runs `drop_matched_ips()` to create `to_block.csv` and `not_blocked.csv` and apply `iptables` rules

- Dashboard tabs
  - Attack: launches `simulator/raw_attack.py` and visualizes `dns_query_log.csv`
  - Firewall: runs the full pipeline and shows logs + charts
  - Comparative Analysis: compares `dns_query_log.csv` (before) vs `not_blocked.csv` (after)

## Configuration
- Rate limiter (`simulator/rate_limiter.py`):
  - `WINDOW_SIZE = 10` seconds
  - `THRESHOLD = 10` requests/window
- Traffic generator (`simulator/query.py`):
  - `TOTAL_UNIQUE_IPS`, `MIN_QUERIES`, `MAX_QUERIES`, `QUERY_INTERVAL`, `QUERY_TYPES`
- YARA rules (`YARA_RULES/rules.yara`): customize detection logic for domains

## Notes and Security Considerations
- `sudo` and `iptables` changes require caution. Consider running in a VM or container. To undo rules, you may need to flush or delete the `iptables` entries that were added.
- Scapy uses raw sockets and typically needs root privileges.
- Large `requirements.txt` includes many packages not strictly required by the core pipeline; prune as needed.

## Troubleshooting
- "File not found" for logs: ensure the `logs/` folder exists at the path referenced in the code.
- No charts in dashboard: verify CSVs are generated (run Firewall tab or `simulator/main.py`).
- `iptables` errors on non-Linux systems: skip `drop_ip.py` or guard the call for your OS.

## License
See `LICENSE`.

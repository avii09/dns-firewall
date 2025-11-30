# DNS Firewall and Attack Simulator - Detailed Project Summary

## 📋 Project Overview

**DNS Firewall and Attack Simulator** is a comprehensive cybersecurity toolkit designed to simulate DNS traffic attacks, implement a multi-layered firewall defense system, and provide real-time visualization and analysis through an interactive dashboard. The project demonstrates a complete pipeline from attack simulation to threat detection and mitigation.

---

## 🎯 What is This Project?

This project is a **DNS-based network security system** that:

1. **Simulates DNS attacks** - Generates realistic DNS traffic (both benign and malicious) using packet crafting
2. **Implements firewall protection** - Uses a 3-stage defense pipeline:
   - Rate limiting (sliding window algorithm)
   - Pattern-based detection (YARA rules)
   - Automatic IP blocking (iptables integration)
3. **Visualizes results** - Provides an interactive Streamlit dashboard for monitoring and analysis

---

## 🏗️ Architecture & Implementation

### Project Structure

```
dns-firewall/
├── dashboard/              # Streamlit web interface
│   ├── app.py             # Main entry point with tab navigation
│   ├── attack.py          # Attack simulation and visualization
│   ├── firewall.py       # Firewall pipeline execution and results
│   └── comparative_analysis.py  # Before/After comparison charts
│
├── simulator/             # Core firewall logic
│   ├── main.py           # Pipeline orchestrator
│   ├── raw_attack.py     # Standalone attack launcher
│   ├── query.py          # DNS packet generation
│   ├── rate_limiter.py   # Rate limiting algorithm
│   ├── filter.py         # YARA rule matching
│   └── drop_ip.py        # IP blocking with iptables
│
├── data/                  # Domain datasets
│   ├── mal_dom.csv       # Malicious domains (100 entries)
│   └── leg_domain.csv    # Legitimate domains (97 entries)
│
├── YARA_RULES/           # Detection signatures
│   └── rules.yara        # Pattern-based detection rules
│
└── logs/                 # Generated output files
    ├── dns_query_log.csv
    ├── rate_limiter_logs.csv
    ├── yara_matched.csv
    ├── to_block.csv
    └── not_blocked.csv
```

---

## 🔄 System Workflow & Logic

### Complete Pipeline Flow

```
1. ATTACK SIMULATION (query.py)
   ↓
   Generate DNS queries (benign + malicious)
   ↓
   [dns_query_log.csv]

2. RATE LIMITING (rate_limiter.py)
   ↓
   Apply sliding window algorithm
   ↓
   [rate_limiter_logs.csv] (Status: OK/DROP)

3. YARA FILTERING (filter.py)
   ↓
   Match domains against YARA rules
   ↓
   [yara_matched.csv] (Malicious IPs identified)

4. IP BLOCKING (drop_ip.py)
   ↓
   Apply iptables rules
   ↓
   [to_block.csv] + [not_blocked.csv]
```

---

## 🧠 Core Algorithms & Logic

### 1. DNS Attack Simulation (`query.py`)

**Purpose**: Generate realistic DNS traffic patterns

**Algorithm**:
- **Multi-threaded traffic generation**: Creates 5 unique IP addresses (randomly legitimate or malicious)
- **IP Address Generation**:
  - **Legitimate IPs**: Private ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
  - **Malicious IPs**: Public suspicious ranges (45.x.x.x, 89.x.x.x, 91.x.x.x, 185.x.x.x, 203.x.x.x, 222.x.x.x)
- **Query Generation**:
  - Each IP sends 1-20 queries (random)
  - Query interval: 0.5 seconds
  - Query types: A (1), NS (2), MX (15), TXT (16), AAAA (28)
  - Domains selected from CSV files (mal_dom.csv or leg_domain.csv)

**Technology**: Scapy for packet crafting
- Creates IP/UDP/DNS layers
- Sends packets to localhost (127.0.0.1:53)
- Logs all queries with timestamps

**Output**: `dns_query_log.csv` with columns:
- Timestamp, Spoofed_IP, Domain, Query_Type, Query_Name

---

### 2. Sliding Window Rate Limiter (`rate_limiter.py`)

**Purpose**: Detect and flag suspicious traffic patterns based on request frequency

**Algorithm**: **Sliding Window Rate Limiting**

**Parameters**:
- `WINDOW_SIZE = 10` seconds
- `THRESHOLD = 10` requests per window

**Logic**:
1. Load DNS query log sorted by timestamp
2. For each IP address, maintain a deque (double-ended queue) of timestamps
3. For each incoming request:
   - Remove timestamps outside the current window (older than 10 seconds)
   - Count remaining requests in the window
   - If count < threshold: Mark as "OK", add timestamp to deque
   - If count >= threshold: Mark as "DROP", don't add timestamp

**Data Structure**: `defaultdict(deque)` - One deque per IP address

**Output**: `rate_limiter_logs.csv` with columns:
- Status (OK/DROP), IP, Domain, Timestamp, Current_Count, Threshold

**Time Complexity**: O(n) where n = number of queries
**Space Complexity**: O(m) where m = number of unique IPs

---

### 3. YARA Pattern Matching (`filter.py`)

**Purpose**: Detect malicious domains using pattern-based signatures

**Algorithm**: **YARA Rule Matching**

**Process**:
1. Load rate limiter logs
2. Filter only "OK" status entries (passed rate limiting)
3. Compile YARA rules from `rules.yara`
4. For each domain:
   - Match against all YARA rules
   - If match found: Extract IP and matched rule names
   - Store in matches list

**YARA Rules Implemented**:

1. **Suspicious_Domain_Keywords**: String matching for known malicious keywords
   - Examples: "funyfile", "1312services", "smartpano", "panel357375", etc.

2. **Potential_DGA_Domain**: Regex patterns for Domain Generation Algorithms
   - Pattern: `[a-z]{6,12}\d{2,4}\.[a-z]{2,}`
   - Detects algorithmically generated domains

3. **Suspicious_TLDs**: Top-level domain detection
   - Flags: .xyz, .top, .store, .ru, .pro, .bio, .bond, .sbs, .ink, .su, .cool, .online

4. **Heuristic_FastFlux_Pattern**: Fast-flux infrastructure detection
   - Patterns like "000webhostapp.com", "panel", sync patterns, etc.

**Output**: `yara_matched.csv` with columns:
- domain, ip, rules (list of matched rule names), timestamp

---

### 4. IP Blocking (`drop_ip.py`)

**Purpose**: Automatically block malicious IPs using system firewall

**Algorithm**:
1. Load YARA matched results
2. Extract unique malicious IP addresses
3. Filter rate limiter logs:
   - **to_block.csv**: All queries from malicious IPs
   - **not_blocked.csv**: All queries from legitimate IPs
4. Apply iptables rules:
   ```bash
   sudo iptables -A INPUT -s <malicious_ip> -j DROP
   ```

**System Integration**: Uses `subprocess` to execute iptables commands

**Output**: 
- `to_block.csv`: Blocked traffic log
- `not_blocked.csv`: Allowed traffic log

---

## 🖥️ Dashboard Pages & Components

### Technology Stack
- **Frontend**: Streamlit (Python web framework)
- **Visualization**: Matplotlib, Seaborn
- **Data Processing**: Pandas, NumPy
- **State Management**: Streamlit Session State (for tab persistence)

### Page 1: 🛡️ Attack Tab (`attack.py`)

**Functionality**:
- Launch raw DNS attack simulation
- Visualize attack traffic in real-time

**Components**:
1. **Attack Button**: Triggers `raw_attack.py` via subprocess
2. **DNS Query Log Table**: Displays all generated queries
3. **Traffic Over Time Chart**: Line chart showing queries per second
4. **Traffic Alert**: 
   - 🚨 High traffic warning if > 30 queries
   - ✅ Normal traffic confirmation if ≤ 30 queries

**Features**:
- Session state persistence (data remains when switching tabs)
- Automatic data refresh after attack completion
- Time-series visualization with 1-second grouping

---

### Page 2: 🔒 Firewall Tab (`firewall.py`)

**Functionality**:
- Execute complete firewall pipeline
- Display comprehensive analysis results

**Components**:

1. **Pipeline Execution**:
   - Button triggers `main.py` (full pipeline)
   - Shows spinner during execution
   - Success/error notifications

2. **Data Tables**:
   - Rate Limiting Logs (with OK/DROP status)
   - YARA Matched Domains
   - Blocked IPs List

3. **Firewall Effectiveness Metrics**:
   - Total Traffic count
   - Blocked queries (count + percentage)
   - Allowed queries (count + percentage)

4. **Visualizations**:

   a. **Rate Limiting Analysis**:
      - Horizontal bar chart: Top 10 IPs approaching threshold
      - Color coding: Green (<50%), Orange (50-75%), Red (>75%)
      - Threshold line at 100%
      - Domain frequency pie chart

   b. **Firewall Blocking Effectiveness**:
      - Pie chart: Blocked vs Allowed traffic
      - Top Blocked IPs pie chart
      - Horizontal bar chart: Top 10 blocked malicious domains

5. **Features**:
   - Comprehensive error handling for missing files
   - Session state for tab persistence
   - Duplicate prevention logic

---

### Page 3: 📊 Comparative Analysis Tab (`comparative_analysis.py`)

**Functionality**:
- Compare traffic before and after firewall filtering
- Analyze firewall effectiveness

**Components**:

1. **Configuration Panel** (Expandable):
   - Time Grouping: 1s, 5s, 10s, 30s, 1min
   - Chart Type: Line, Area, Bar
   - Show Blocked Traffic: Toggle
   - Highlight Anomalies: Toggle

2. **Main Visualization**:
   - **Line Chart**: Before Attack vs After Filtering (with optional Blocked overlay)
   - **Area Chart**: Stacked visualization showing allowed (green) and blocked (red) traffic
   - **Bar Chart**: Side-by-side comparison

3. **Key Metrics Dashboard**:
   - Total Queries (before filtering)
   - Allowed Queries (after filtering)
   - Blocked Queries (difference)
   - Block Rate Percentage
   - Peak Traffic (value + timestamp)

4. **Traffic Distribution**:
   - Pie chart: Allowed vs Blocked traffic
   - Custom legend with counts

5. **Features**:
   - Interactive configuration
   - Session state for settings persistence
   - Automatic data refresh

---

## 🛠️ Technologies Used

### Core Technologies

1. **Python 3.8+**: Main programming language
2. **Scapy 2.6.1**: Network packet manipulation and DNS packet crafting
3. **Pandas 2.3.3**: Data processing and CSV handling
4. **YARA-Python 1.7.7**: Pattern matching engine for malware detection
5. **Streamlit 1.51.0**: Web dashboard framework
6. **Matplotlib 3.10.7**: Data visualization
7. **Seaborn 0.13.2**: Statistical visualization
8. **NumPy 2.3.5**: Numerical computations

### System Integration

- **iptables**: Linux firewall for IP blocking
- **subprocess**: System command execution
- **threading**: Concurrent DNS query generation
- **os.path**: Cross-platform path handling

---

## 🔐 Security Features

### Multi-Layer Defense Strategy

1. **Layer 1 - Rate Limiting**:
   - Prevents DDoS attacks
   - Detects high-frequency query patterns
   - Configurable threshold (10 queries/10 seconds)

2. **Layer 2 - Pattern Detection**:
   - YARA-based signature matching
   - Detects known malicious patterns
   - Heuristic-based DGA detection
   - TLD-based filtering

3. **Layer 3 - IP Blocking**:
   - Automatic iptables rule application
   - Permanent blocking of malicious IPs
   - Logging of blocked/allowed traffic

---

## 📊 Data Flow

### Input Data
- **mal_dom.csv**: 100 malicious domain names
- **leg_domain.csv**: 97 legitimate domain names
- **rules.yara**: 4 YARA rule sets with multiple patterns

### Processing Pipeline
```
CSV Files → DNS Queries → Rate Limiting → YARA Matching → IP Blocking
```

### Output Data
- **dns_query_log.csv**: Raw DNS queries (all traffic)
- **rate_limiter_logs.csv**: Rate-limited traffic (OK/DROP status)
- **yara_matched.csv**: Domains matching YARA rules
- **to_block.csv**: Traffic from malicious IPs
- **not_blocked.csv**: Traffic from legitimate IPs

---

## 🎨 Key Features & Innovations

1. **Real-time Visualization**: Live traffic monitoring with interactive charts
2. **State Persistence**: Session state management prevents data loss on tab switching
3. **Modular Architecture**: Each component is independent and testable
4. **Portable Paths**: All paths are relative, making the project portable
5. **Comprehensive Logging**: Every stage produces detailed CSV logs
6. **Error Handling**: Robust error handling for missing files and edge cases
7. **Multi-threaded Simulation**: Realistic concurrent traffic generation

---

## 🚀 Usage Scenarios

1. **Security Research**: Study DNS attack patterns and defense mechanisms
2. **Education**: Learn about network security, rate limiting, and pattern matching
3. **Testing**: Validate firewall rules and detection algorithms
4. **Monitoring**: Real-time DNS traffic analysis and threat detection

---

## ⚙️ Configuration Parameters

### Attack Simulation (`query.py`)
- `TOTAL_UNIQUE_IPS = 5`: Number of unique IPs to simulate
- `MIN_QUERIES = 1`: Minimum queries per IP
- `MAX_QUERIES = 20`: Maximum queries per IP
- `QUERY_INTERVAL = 0.5`: Seconds between queries
- `QUERY_TYPES = [1, 2, 15, 16, 28]`: DNS query types (A, NS, MX, TXT, AAAA)

### Rate Limiter (`rate_limiter.py`)
- `WINDOW_SIZE = 10`: Time window in seconds
- `THRESHOLD = 10`: Maximum queries allowed per window

### YARA Rules (`rules.yara`)
- 4 rule sets with 20+ detection patterns
- Customizable regex and string patterns

---

## 🔧 Technical Implementation Details

### Path Resolution
- Uses `os.path.abspath(__file__)` to get current file location
- Calculates `PROJECT_ROOT` dynamically
- All paths use `os.path.join()` for cross-platform compatibility

### Threading Model
- One thread per IP address
- Concurrent query generation
- Thread synchronization with `join()`

### Data Structures
- **deque**: Efficient sliding window (O(1) append/popleft)
- **defaultdict**: Automatic dictionary initialization
- **DataFrame**: Pandas for efficient data manipulation

### Error Handling
- Try-except blocks for file operations
- Graceful degradation (empty DataFrames on errors)
- User-friendly error messages in dashboard

---

## 📈 Performance Characteristics

- **Rate Limiter**: O(n) time complexity, O(m) space (n=queries, m=IPs)
- **YARA Matching**: O(n × r) where n=domains, r=rules
- **Dashboard**: Real-time rendering with Streamlit's reactive framework

---

## 🎓 Learning Outcomes

This project demonstrates:
- Network packet crafting and manipulation
- Multi-layered security architecture
- Real-time data visualization
- Pattern matching and signature-based detection
- System-level integration (iptables)
- Web dashboard development
- Data pipeline orchestration

---

## 🔮 Future Enhancements

Potential improvements:
- Machine learning-based anomaly detection
- Real-time packet capture (not just simulation)
- Database integration for historical analysis
- Multi-protocol support (not just DNS)
- Cloud deployment options
- API endpoints for integration
- Advanced visualization (network graphs, heatmaps)

---

## 📝 Conclusion

This DNS Firewall project is a comprehensive cybersecurity toolkit that combines attack simulation, multi-layered defense mechanisms, and interactive visualization. It demonstrates practical implementation of rate limiting algorithms, pattern-based detection, and system-level security controls, making it an excellent educational and research tool for network security.


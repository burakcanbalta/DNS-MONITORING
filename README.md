# 🛡️ DNS Monitoring Tool

A real-time DNS monitoring and threat detection system designed for SOCs, security teams, and network administrators. Capture DNS queries, analyze them for malicious activity, and detect DNS tunneling attacks with alerting and reporting capabilities.

---

## 🚀 Quick Start

### 1. Requirements

```txt
dpkt==1.9.8
requests==2.31.0
```

### 2. Installation

```bash
# Install required packages
pip install dpkt requests
```

### 3. Usage Examples

```bash
# Start DNS monitoring on interface eth0 (requires root)
sudo python dns_monitor.py --monitor --interface eth0

# Monitor for 10 minutes
sudo python dns_monitor.py --monitor --interface eth0 --duration 600

# Generate a report for the last 24 hours (JSON)
python dns_monitor.py --report --hours 24 --format json

# Add a malicious domain to threat intelligence
python dns_monitor.py --add-threat "malicious-domain.com" --threat-type "MALWARE"
```

---

## 🎯 Purpose

Monitor DNS traffic in real-time, detect malicious domains and suspicious patterns (including DGA and DNS tunneling), and produce actionable alerts and reports for SOC analysts and incident responders.

---

## 🔍 Features

- **Real-time DNS Monitoring**
  - Raw packet capture to collect DNS queries
  - tcpdump fallback support
  - Multi-interface monitoring and filtering

- **Threat Detection**
  - Malicious domain lookup (threat intelligence feed)
  - DGA (Domain Generation Algorithm) detection heuristics
  - Suspicious TLD identification (e.g., .tk, .ml, .xyz)
  - Query pattern analysis and anomaly detection

- **DNS Tunneling Detection**
  - High-entropy domain detection
  - Abnormal query volume analysis
  - Data exfiltration pattern recognition
  - Real-time alerting

- **Intelligence & Reporting**
  - Threat intelligence database (editable)
  - Export reports to JSON / CSV / TXT
  - Historical analysis and event logging

---

## 🛠️ How It Works (High Level)

1. The tool captures DNS packets from the selected interface (raw sockets or tcpdump).
2. Each DNS query is parsed and analyzed for suspicious characteristics:
   - Unusually long or high-entropy labels.
   - High frequency queries from a single client.
   - Matches against threat intelligence.
   - Known DGA-like patterns.
3. Events that meet detection criteria are logged, stored in the local DB, and trigger alerts (console, webhook, etc.).
4. Periodic or on-demand reports can be generated from stored scan data.

---

## 🧩 CLI Reference

```bash
# Monitor mode (real-time)
sudo python dns_monitor.py --monitor --interface eth0 [--duration SECONDS] [--output json|csv|txt]

# Add a threat to the intelligence DB
python dns_monitor.py --add-threat "bad-domain.com" --threat-type "MALWARE"

# Remove a threat
python dns_monitor.py --remove-threat "bad-domain.com"

# Generate a report
python dns_monitor.py --report --hours 24 --format json

# Show help
python dns_monitor.py --help
```

---

## 🧪 Use Cases

### SOC Monitoring
```bash
# 24/7 DNS monitoring on the perimeter
sudo python dns_monitor.py --monitor --interface eth0
```
**Example alert:**
```
🚨 HIGH ALERT: DNS_TUNNELING - 192.168.1.100 -> dgadomain12345.com
```

### Incident Response
```bash
# Retrieve DNS query history for a suspicious IP
python dns_monitor.py --report --hours 48 --format json --filter-ip 192.168.1.100
```

### Threat Hunting
```bash
# Add a new malicious domain to the local intelligence DB
python dns_monitor.py --add-threat "new-malware-domain.com" --threat-type "MALWARE"
```

---

## 🐞 Troubleshooting

- **Permission errors**: Packet capture usually requires root privileges. Run with `sudo` or configure appropriate capabilities.
- **tcpdump fallback**: If raw socket capture fails, the tool will attempt to use `tcpdump`—ensure tcpdump is installed.
- **High volume**: For very high traffic, consider sampling, filtering, or running on a dedicated sensor.

---

## 📈 Performance & Scaling

- Use interface-level filters to reduce noise (e.g., capture only UDP/53).
- Persist events to a lightweight DB and rotate logs periodically.
- For enterprise deployments, forward alerts to a SIEM or a central collector.

---

## 🧾 Output Examples

```bash
# Console example
🚀 DNS Monitor started on eth0
🔍 Query: client=10.0.0.5 qname=dgadomain12345.com entropy=0.93 tags=[HIGH_ENTROPY,DNS_TUNNEL]
🚨 ALERT: DNS_TUNNELING detected from 10.0.0.5 -> dgadomain12345.com
```

```json
# Report sample (JSON)
{
  "timestamp": "2025-10-22T18:00:00Z",
  "client": "10.0.0.5",
  "qname": "dgadomain12345.com",
  "reason": ["HIGH_ENTROPY","THREAT_INTEL_MATCH"],
  "threat_type": "DGA"
}
```

---

## 🤝 Contributing

- Fork the repo
- Create a feature branch
- Submit a pull request with tests and documentation
- Areas for contribution: DGA detection improvements, integrations (Slack, SIEM), UI/dashboard, performance tuning

---

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

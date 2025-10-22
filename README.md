# 🛡️ DNS Monitoring Tool

A real-time DNS monitoring and threat detection system designed for SOCs, security teams, and network administrators. Capture DNS queries, analyze them for malicious activity, and detect DNS tunneling attacks with alerting and reporting capabilities.

---

## 🎯 What It Does

This tool monitors DNS traffic in real-time to detect malicious domains, suspicious patterns (including DGA and DNS tunneling), and other anomalies. It produces actionable alerts, logs, and detailed reports for security analysis and incident response.

**Key Capabilities:**

* Real-time DNS monitoring across multiple network interfaces.
* Threat detection using local intelligence and DGA heuristics.
* DNS tunneling detection via entropy analysis and query volume monitoring.
* Historical reporting and export in JSON, CSV, or TXT formats.
* Real-time alerts via console or webhook integrations.

---

## 🚀 Quick Start

### 1. Requirements

```txt
dpkt==1.9.8
requests==2.31.0
```

### 2. Installation

```bash
# Install required Python packages
pip install dpkt requests
```

---

## 🛠️ How It Works

1. Captures DNS packets from the selected interface (raw sockets or tcpdump fallback).
2. Parses each DNS query and analyzes for:

   * High entropy domain names
   * Unusually frequent queries from a single client
   * Matches against threat intelligence
   * DGA-like patterns
3. Logs suspicious events, stores them in a local database, and triggers alerts.
4. Generates reports on-demand or periodically for analysis and compliance.

---

## ⚡ Usage Examples

```bash
# Start real-time monitoring on eth0
sudo python dns_monitor.py --monitor --interface eth0

# Monitor for 10 minutes
sudo python dns_monitor.py --monitor --interface eth0 --duration 600

# Generate report for last 24 hours (JSON)
python dns_monitor.py --report --hours 24 --format json

# Add a malicious domain to threat intelligence DB
python dns_monitor.py --add-threat "malicious-domain.com" --threat-type "MALWARE"
```

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

**SOC Monitoring**

```bash
# 24/7 DNS monitoring on perimeter
sudo python dns_monitor.py --monitor --interface eth0
```

**Example Alert:**

```
🚨 HIGH ALERT: DNS_TUNNELING - 192.168.1.100 -> dgadomain12345.com
```

**Incident Response**

```bash
# Retrieve DNS query history for a suspicious IP
python dns_monitor.py --report --hours 48 --format json --filter-ip 192.168.1.100
```

**Threat Hunting**

```bash
# Add a new malicious domain to intelligence DB
python dns_monitor.py --add-threat "new-malware-domain.com" --threat-type "MALWARE"
```

---

## 🧾 Output Examples

```bash
# Console example
🚀 DNS Monitor started on eth0
🔍 Query: client=10.0.0.5 qname=dgadomain12345.com entropy=0.93 tags=[HIGH_ENTROPY,DNS_TUNNEL]
🚨 ALERT: DNS_TUNNELING detected from 10.0.0.5 -> dgadomain12345.com
```

```json
# Report example (JSON)
{
  "timestamp": "2025-10-22T18:00:00Z",
  "client": "10.0.0.5",
  "qname": "dgadomain12345.com",
  "reason": ["HIGH_ENTROPY","THREAT_INTEL_MATCH"],
  "threat_type": "DGA"
}
```

---

## 🔍 Features

* **Real-time DNS Monitoring**: Capture raw DNS packets, multi-interface support, tcpdump fallback.
* **Threat Detection**: Detect malicious domains, DGA domains, suspicious TLDs, anomalous query patterns.
* **DNS Tunneling Detection**: High-entropy domain analysis, data exfiltration pattern recognition, real-time alerts.
* **Intelligence & Reporting**: Threat database, JSON/CSV/TXT reports, historical analysis, event logging.

---

## 🐞 Troubleshooting

* **Permission errors**: Requires root or proper packet capture capabilities.
* **High traffic volume**: Use filters, sampling, or a dedicated sensor.
* **tcpdump fallback**: Ensure tcpdump installed for raw socket fallback.

---

## 📈 Performance & Scaling

* Interface-level filters to reduce noise (UDP/53).
* Persist events in lightweight DB, rotate logs periodically.
* Forward alerts to SIEM or central collector in enterprise environments.

---

## 🤝 Contributing

* Fork the repo.
* Create a feature branch.
* Submit a pull request with tests and documentation.
* Contribution areas: DGA detection, alert integrations, dashboard/UI, performance tuning.

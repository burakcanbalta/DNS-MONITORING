import dpkt
import socket
import threading
import time
import sqlite3
import json
import requests
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import argparse
import subprocess
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Set
import struct

@dataclass
class DNSQuery:
    timestamp: datetime
    source_ip: str
    domain: str
    query_type: str
    response_code: int
    packet_size: int

class DNSMonitor:
    def __init__(self, db_path="dns_monitor.db"):
        self.db_path = db_path
        self.dns_queries = defaultdict(list)
        self.domain_stats = defaultdict(Counter)
        self.suspicious_domains = set()
        self.whitelist_domains = set()
        self.is_monitoring = False
        self.init_database()
        self.load_threat_intelligence()
        
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                domain TEXT,
                query_type TEXT,
                response_code INTEGER,
                packet_size INTEGER,
                is_suspicious BOOLEAN DEFAULT FALSE,
                threat_type TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                threat_type TEXT,
                confidence INTEGER,
                first_seen DATETIME,
                last_seen DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                source_ip TEXT,
                domain TEXT,
                description TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_tunneling_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                domain TEXT,
                query_count INTEGER,
                data_volume INTEGER,
                entropy_score REAL,
                detection_method TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def load_threat_intelligence(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM threat_intelligence")
        for row in cursor.fetchall():
            self.suspicious_domains.add(row[0])
        conn.close()
        
        default_malicious_domains = [
            "evil.com", "malware.com", "phishing.com", "botnet.com"
        ]
        for domain in default_malicious_domains:
            self.suspicious_domains.add(domain)

    def start_monitoring(self, interface="eth0", duration=0):
        self.is_monitoring = True
        print(f"🔍 Starting DNS monitoring on interface {interface}")
        
        if duration > 0:
            monitor_thread = threading.Thread(target=self._monitor_with_timeout, args=(interface, duration))
        else:
            monitor_thread = threading.Thread(target=self._capture_packets, args=(interface,))
        
        monitor_thread.start()
        
        analysis_thread = threading.Thread(target=self._continuous_analysis)
        analysis_thread.start()
        
        try:
            while self.is_monitoring:
                time.sleep(1)
        except KeyboardInterrupt:
            self.is_monitoring = False
            print("\n🛑 DNS monitoring stopped")

    def _monitor_with_timeout(self, interface, duration):
        self._capture_packets(interface)
        time.sleep(duration)
        self.is_monitoring = False

    def _capture_packets(self, interface):
        try:
            if os.name == 'nt':
                print("❌ Raw packet capture not supported on Windows")
                return
            
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            while self.is_monitoring:
                packet, addr = sock.recvfrom(65535)
                self._process_packet(packet)
                
        except Exception as e:
            print(f"❌ Packet capture error: {e}")
            self._fallback_capture(interface)

    def _fallback_capture(self, interface):
        print("🔄 Using fallback capture method (tcpdump)")
        try:
            process = subprocess.Popen(
                ['tcpdump', '-i', interface, '-n', 'port', '53', '-l'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            for line in process.stdout:
                if not self.is_monitoring:
                    break
                self._parse_tcpdump_line(line)
                
        except Exception as e:
            print(f"❌ Fallback capture failed: {e}")

    def _parse_tcpdump_line(self, line):
        try:
            if 'A?' not in line and 'AAAA?' not in line:
                return
                
            parts = line.split()
            if len(parts) < 8:
                return
                
            timestamp = datetime.now()
            source_ip = parts[2].split('.')[0] if '.' in parts[2] else parts[2]
            domain = None
            
            for part in parts:
                if part.endswith('.') and 'A?' in parts:
                    domain = part[:-1]
                    break
            
            if domain and len(domain) > 3:
                query = DNSQuery(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    domain=domain,
                    query_type="A",
                    response_code=0,
                    packet_size=len(line)
                )
                self._analyze_dns_query(query)
                
        except Exception as e:
            print(f"❌ TCPdump parsing error: {e}")

    def _process_packet(self, packet):
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            
            if not isinstance(eth.data, dpkt.ip.IP):
                return
                
            ip = eth.data
            
            if not isinstance(ip.data, (dpkt.udp.UDP, dpkt.tcp.TCP)):
                return
            
            transport = ip.data
            
            if transport.dport == 53 or transport.sport == 53:
                try:
                    dns = dpkt.dns.DNS(transport.data)
                    self._process_dns_packet(dns, ip)
                except:
                    pass
                    
        except Exception as e:
            pass

    def _process_dns_packet(self, dns, ip):
        timestamp = datetime.now()
        source_ip = socket.inet_ntoa(ip.src)
        
        for query in dns.qd:
            if query.type in [dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA, dpkt.dns.DNS_CNAME]:
                domain = query.name.decode('utf-8') if isinstance(query.name, bytes) else query.name
                
                dns_query = DNSQuery(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    domain=domain,
                    query_type=self._get_query_type_name(query.type),
                    response_code=dns.rcode,
                    packet_size=len(dns)
                )
                
                self._analyze_dns_query(dns_query)

    def _get_query_type_name(self, query_type):
        type_map = {
            dpkt.dns.DNS_A: 'A',
            dpkt.dns.DNS_AAAA: 'AAAA',
            dpkt.dns.DNS_CNAME: 'CNAME',
            dpkt.dns.DNS_MX: 'MX',
            dpkt.dns.DNS_TXT: 'TXT',
            dpkt.dns.DNS_NS: 'NS'
        }
        return type_map.get(query_type, 'UNKNOWN')

    def _analyze_dns_query(self, query):
        self.dns_queries[query.source_ip].append(query)
        self.domain_stats[query.domain]['query_count'] += 1
        self.domain_stats[query.domain]['last_seen'] = query.timestamp
        
        is_suspicious = False
        threat_type = None
        
        if self._is_malicious_domain(query.domain):
            is_suspicious = True
            threat_type = "KNOWN_MALICIOUS"
            self._log_security_event("MALICIOUS_DOMAIN", query.source_ip, query.domain, 
                                   f"Known malicious domain: {query.domain}", "HIGH")
        
        elif self._is_dga_domain(query.domain):
            is_suspicious = True
            threat_type = "DGA"
            self._log_security_event("DGA_DOMAIN", query.source_ip, query.domain,
                                   f"Potential DGA domain: {query.domain}", "MEDIUM")
        
        elif self._is_suspicious_tld(query.domain):
            is_suspicious = True
            threat_type = "SUSPICIOUS_TLD"
            self._log_security_event("SUSPICIOUS_TLD", query.source_ip, query.domain,
                                   f"Suspicious TLD in domain: {query.domain}", "LOW")
        
        self._save_dns_query(query, is_suspicious, threat_type)
        
        if len(self.dns_queries[query.source_ip]) % 10 == 0:
            self._check_dns_tunneling(query.source_ip)

    def _is_malicious_domain(self, domain):
        return domain in self.suspicious_domains

    def _is_dga_domain(self, domain):
        if len(domain) < 8:
            return False
            
        vowel_count = sum(1 for char in domain if char.lower() in 'aeiou')
        consonant_count = sum(1 for char in domain if char.lower() in 'bcdfghjklmnpqrstvwxyz')
        
        if consonant_count == 0:
            return False
            
        vowel_ratio = vowel_count / consonant_count
        
        entropy = self._calculate_entropy(domain)
        
        has_numbers = any(char.isdigit() for char in domain)
        
        return (entropy > 3.5 and vowel_ratio < 0.3) or (has_numbers and entropy > 3.0)

    def _is_suspicious_tld(self, domain):
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club']
        return any(domain.endswith(tld) for tld in suspicious_tlds)

    def _calculate_entropy(self, text):
        if not text:
            return 0
            
        entropy = 0
        for char in set(text):
            p_x = float(text.count(char)) / len(text)
            if p_x > 0:
                entropy += - p_x * (p_x and math.log(p_x, 2))
        return entropy

    def _check_dns_tunneling(self, source_ip):
        queries = self.dns_queries.get(source_ip, [])
        if len(queries) < 20:
            return
            
        recent_queries = [q for q in queries if (datetime.now() - q.timestamp).seconds < 300]
        
        if len(recent_queries) < 15:
            return
        
        total_volume = sum(q.packet_size for q in recent_queries)
        avg_query_length = sum(len(q.domain) for q in recent_queries) / len(recent_queries)
        
        unique_domains = len(set(q.domain for q in recent_queries))
        query_ratio = unique_domains / len(recent_queries)
        
        high_entropy_domains = sum(1 for q in recent_queries if self._calculate_entropy(q.domain) > 3.5)
        entropy_ratio = high_entropy_domains / len(recent_queries)
        
        is_tunneling = (
            avg_query_length > 50 or
            query_ratio > 0.8 or
            entropy_ratio > 0.6 or
            len(recent_queries) > 100
        )
        
        if is_tunneling:
            self._log_dns_tunneling(source_ip, recent_queries[0].domain, len(recent_queries), total_volume, entropy_ratio)
            self._log_security_event("DNS_TUNNELING", source_ip, recent_queries[0].domain,
                                   f"Potential DNS tunneling detected: {len(recent_queries)} queries", "HIGH")

    def _log_dns_tunneling(self, source_ip, domain, query_count, data_volume, entropy_score):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO dns_tunneling_detections 
            (source_ip, domain, query_count, data_volume, entropy_score, detection_method)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (source_ip, domain, query_count, data_volume, entropy_score, "BEHAVIORAL"))
        conn.commit()
        conn.close()

    def _save_dns_query(self, query, is_suspicious, threat_type):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO dns_queries 
            (timestamp, source_ip, domain, query_type, response_code, packet_size, is_suspicious, threat_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (query.timestamp, query.source_ip, query.domain, query.query_type, 
              query.response_code, query.packet_size, is_suspicious, threat_type))
        conn.commit()
        conn.close()

    def _log_security_event(self, event_type, source_ip, domain, description, severity):
        print(f"🚨 {severity} ALERT: {event_type} - {source_ip} -> {domain}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_events 
            (event_type, source_ip, domain, description, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (event_type, source_ip, domain, description, severity))
        conn.commit()
        conn.close()

    def _continuous_analysis(self):
        while self.is_monitoring:
            time.sleep(60)
            self._analyze_query_patterns()
            self._cleanup_old_data()

    def _analyze_query_patterns(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, COUNT(*) as query_count 
            FROM dns_queries 
            WHERE timestamp > datetime('now', '-5 minutes')
            GROUP BY source_ip 
            HAVING query_count > 100
        ''')
        
        for row in cursor.fetchall():
            source_ip, count = row
            self._log_security_event("HIGH_QUERY_VOLUME", source_ip, "N/A", 
                                   f"High DNS query volume: {count} queries in 5 minutes", "MEDIUM")
        
        conn.close()

    def _cleanup_old_data(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM dns_queries WHERE timestamp < datetime('now', '-7 days')")
        cursor.execute("DELETE FROM security_events WHERE timestamp < datetime('now', '-30 days')")
        conn.commit()
        conn.close()

    def generate_report(self, hours=24, output_format='text'):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) as total_queries,
                   COUNT(DISTINCT source_ip) as unique_ips,
                   COUNT(DISTINCT domain) as unique_domains,
                   SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious_queries
            FROM dns_queries 
            WHERE timestamp > datetime('now', '-? hours')
        ''', (hours,))
        
        stats = cursor.fetchone()
        
        cursor.execute('''
            SELECT event_type, severity, COUNT(*) as count
            FROM security_events 
            WHERE timestamp > datetime('now', '-? hours')
            GROUP BY event_type, severity
            ORDER BY count DESC
        ''', (hours,))
        
        events = cursor.fetchall()
        
        cursor.execute('''
            SELECT domain, COUNT(*) as query_count
            FROM dns_queries 
            WHERE timestamp > datetime('now', '-? hours')
            GROUP BY domain 
            ORDER BY query_count DESC 
            LIMIT 10
        ''', (hours,))
        
        top_domains = cursor.fetchall()
        
        conn.close()
        
        report_data = {
            'time_period_hours': hours,
            'total_queries': stats[0],
            'unique_ips': stats[1],
            'unique_domains': stats[2],
            'suspicious_queries': stats[3],
            'security_events': [{'type': e[0], 'severity': e[1], 'count': e[2]} for e in events],
            'top_domains': [{'domain': d[0], 'count': d[1]} for d in top_domains]
        }
        
        if output_format == 'json':
            return json.dumps(report_data, indent=2, default=str)
        elif output_format == 'csv':
            csv_output = "metric,value\n"
            csv_output += f"total_queries,{stats[0]}\n"
            csv_output += f"unique_ips,{stats[1]}\n"
            csv_output += f"unique_domains,{stats[2]}\n"
            csv_output += f"suspicious_queries,{stats[3]}\n"
            return csv_output
        else:
            output = f"DNS Monitoring Report (Last {hours} hours)\n"
            output += "=" * 50 + "\n"
            output += f"Total Queries: {stats[0]}\n"
            output += f"Unique IPs: {stats[1]}\n"
            output += f"Unique Domains: {stats[2]}\n"
            output += f"Suspicious Queries: {stats[3]}\n\n"
            
            output += "Security Events:\n"
            for event in events:
                output += f"  {event[0]} ({event[1]}): {event[2]} occurrences\n"
            
            output += "\nTop Domains:\n"
            for domain in top_domains:
                output += f"  {domain[0]}: {domain[1]} queries\n"
            
            return output

    def add_threat_intelligence(self, domain, threat_type="MALICIOUS", confidence=80):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO threat_intelligence 
            (domain, threat_type, confidence, first_seen, last_seen)
            VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM threat_intelligence WHERE domain = ?), datetime('now')), datetime('now'))
        ''', (domain, threat_type, confidence, domain))
        
        conn.commit()
        conn.close()
        
        self.suspicious_domains.add(domain)
        print(f"✅ Added to threat intelligence: {domain}")

def main():
    parser = argparse.ArgumentParser(description='DNS Security Monitor')
    parser.add_argument('--monitor', action='store_true', help='Start DNS monitoring')
    parser.add_argument('--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('--duration', type=int, default=0, help='Monitoring duration in seconds (0 for continuous)')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--hours', type=int, default=24, help='Hours for report generation')
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text', help='Report format')
    parser.add_argument('--add-threat', help='Add domain to threat intelligence')
    parser.add_argument('--threat-type', default='MALICIOUS', help='Threat type for added domain')
    
    args = parser.parse_args()
    
    monitor = DNSMonitor()
    
    if args.add_threat:
        monitor.add_threat_intelligence(args.add_threat, args.threat_type)
        return
    
    if args.monitor:
        monitor.start_monitoring(args.interface, args.duration)
    
    if args.report:
        report = monitor.generate_report(args.hours, args.format)
        print(report)

if __name__ == "__main__":
    import math
    main()

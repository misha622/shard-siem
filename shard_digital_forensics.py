#!/usr/bin/env python3

"""
SHARD Digital Forensics Module
Цифровая криминалистика — сбор и анализ доказательств
PCAP анализ, memory forensics, timeline reconstruction

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import re
import json
import time
import threading
import hashlib
import struct
import sqlite3
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml


class EvidenceType(Enum):
    PCAP = "pcap"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    LOG_FILE = "log_file"
    REGISTRY = "registry"
    PREFETCH = "prefetch"
    EVENT_LOG = "event_log"
    BROWSER_HISTORY = "browser_history"
    SHELLBAG = "shellbag"
    JUMP_LIST = "jump_list"
    LNK_FILE = "lnk_file"
    MFT = "mft"
    USN_JOURNAL = "usn_journal"
    AMCACHE = "amcache"
    SHIMCACHE = "shimcache"
    SRUM = "srum"
    RECYCLE_BIN = "recycle_bin"


class EvidenceSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ForensicsConfig:

    evidence_dir: str = "./data/forensics/evidence/"
    cases_dir: str = "./data/forensics/cases/"
    reports_dir: str = "./data/forensics/reports/"

    pcap_analysis_enabled: bool = True
    memory_analysis_enabled: bool = True
    disk_analysis_enabled: bool = True
    log_analysis_enabled: bool = True

    tools_path: str = "/usr/bin"
    volatility_path: str = "/opt/volatility3"
    sleuthkit_path: str = "/usr/bin"

    max_pcap_size_mb: int = 1024
    max_memory_dump_size_mb: int = 4096
    max_file_size_mb: int = 100

    auto_analyze_alerts: bool = True
    auto_create_timeline: bool = True
    auto_generate_report: bool = True


@dataclass
class Evidence:
    id: str
    case_id: str
    type: EvidenceType
    source: str
    path: str
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    size_bytes: int = 0
    collected_at: float = field(default_factory=time.time)
    collected_by: str = "SHARD"
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    chain_of_custody: List[Dict] = field(default_factory=list)


@dataclass
class ForensicFinding:
    id: str
    evidence_id: str
    name: str
    description: str
    severity: EvidenceSeverity
    artifact_type: str
    timestamp: Optional[float] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    data: Dict[str, Any] = field(default_factory=dict)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: List[Dict] = field(default_factory=list)


class PCAPAnalyzer:

    def __init__(self, config: ForensicsConfig, logger=None):
        self.config = config
        self.logger = logger
        self.scapy_available = self._check_scapy()

    def _check_scapy(self) -> bool:
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
            return True
        except ImportError:
            return False

    def analyze(self, pcap_path: str, evidence_id: str) -> List[ForensicFinding]:
        findings = []

        if not self.scapy_available:
            if self.logger:
                self.logger.warning("Scapy not available, limited PCAP analysis")
            return self._analyze_with_tshark(pcap_path, evidence_id)

        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw

            packets = rdpcap(pcap_path)

            ips = set()
            ports = set()
            protocols = defaultdict(int)

            for pkt in packets:
                if IP in pkt:
                    ips.add(pkt[IP].src)
                    ips.add(pkt[IP].dst)

                    if TCP in pkt:
                        protocols['tcp'] += 1
                        ports.add(pkt[TCP].sport)
                        ports.add(pkt[TCP].dport)

                        if pkt[TCP].dport in [4444, 5555, 6666, 7777, 8888, 1337, 31337]:
                            findings.append(ForensicFinding(
                                id=f"PCAP-SUSPICIOUS-PORT-{len(findings)}",
                                evidence_id=evidence_id,
                                name="Suspicious Port Connection",
                                description=f"Connection to suspicious port {pkt[TCP].dport}",
                                severity=EvidenceSeverity.HIGH,
                                artifact_type="network_connection",
                                timestamp=float(pkt.time),
                                data={
                                    'src_ip': pkt[IP].src,
                                    'dst_ip': pkt[IP].dst,
                                    'src_port': pkt[TCP].sport,
                                    'dst_port': pkt[TCP].dport
                                },
                                mitre_tactics=['Command and Control'],
                                mitre_techniques=['T1071'],
                                iocs=[{'type': 'ip', 'value': pkt[IP].dst}]
                            ))

                    elif UDP in pkt:
                        protocols['udp'] += 1

                        if DNS in pkt and pkt[DNS].qr == 0:
                            dns_query = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ''

                            if len(dns_query) > 50:
                                findings.append(ForensicFinding(
                                    id=f"PCAP-DNS-TUNNEL-{len(findings)}",
                                    evidence_id=evidence_id,
                                    name="Potential DNS Tunneling",
                                    description=f"Long DNS query: {dns_query[:50]}...",
                                    severity=EvidenceSeverity.HIGH,
                                    artifact_type="dns_query",
                                    timestamp=float(pkt.time),
                                    data={'query': dns_query, 'length': len(dns_query)},
                                    mitre_tactics=['Command and Control'],
                                    mitre_techniques=['T1572']
                                ))

                            entropy = self._calculate_entropy(dns_query)
                            if entropy > 3.5:
                                findings.append(ForensicFinding(
                                    id=f"PCAP-DGA-{len(findings)}",
                                    evidence_id=evidence_id,
                                    name="Potential DGA Domain",
                                    description=f"High entropy DNS query: {dns_query} (entropy: {entropy:.2f})",
                                    severity=EvidenceSeverity.MEDIUM,
                                    artifact_type="dns_query",
                                    timestamp=float(pkt.time),
                                    data={'query': dns_query, 'entropy': entropy}
                                ))

                    elif pkt[IP].proto == 1:
                        protocols['icmp'] += 1

                        if Raw in pkt and len(pkt[Raw].load) > 100:
                            findings.append(ForensicFinding(
                                id=f"PCAP-ICMP-TUNNEL-{len(findings)}",
                                evidence_id=evidence_id,
                                name="Potential ICMP Tunneling",
                                description=f"Large ICMP packet: {len(pkt[Raw].load)} bytes",
                                severity=EvidenceSeverity.HIGH,
                                artifact_type="icmp",
                                timestamp=float(pkt.time),
                                data={'size': len(pkt[Raw].load)},
                                mitre_tactics=['Command and Control'],
                                mitre_techniques=['T1095']
                            ))

            findings.append(ForensicFinding(
                id=f"PCAP-STATS-{evidence_id[:8]}",
                evidence_id=evidence_id,
                name="PCAP Statistics",
                description=f"Analyzed {len(packets)} packets",
                severity=EvidenceSeverity.INFO,
                artifact_type="statistics",
                data={
                    'total_packets': len(packets),
                    'unique_ips': len(ips),
                    'unique_ports': len(ports),
                    'protocols': dict(protocols)
                }
            ))

        except Exception as e:
            if self.logger:
                self.logger.error(f"PCAP analysis error: {e}")

        return findings

    def _analyze_with_tshark(self, pcap_path: str, evidence_id: str) -> List[ForensicFinding]:
        findings = []

        try:
            result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
            if result.returncode != 0:
                return findings

            cmd = ['tshark', '-r', pcap_path, '-q', '-z', 'io,stat,0']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                findings.append(ForensicFinding(
                    id=f"PCAP-TSHARK-{evidence_id[:8]}",
                    evidence_id=evidence_id,
                    name="PCAP Statistics (tshark)",
                    description="Basic PCAP statistics",
                    severity=EvidenceSeverity.INFO,
                    artifact_type="statistics",
                    data={'output': result.stdout[:1000]}
                ))

            cmd = ['tshark', '-r', pcap_path, '-Y', 'tcp.port in {4444 5555 6666 7777 8888 1337 31337}', '-T', 'fields',
                   '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.port']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n')[:10]:
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        findings.append(ForensicFinding(
                            id=f"PCAP-SUSPICIOUS-{hash(line) % 10000}",
                            evidence_id=evidence_id,
                            name="Suspicious Connection",
                            description=f"Connection to suspicious port",
                            severity=EvidenceSeverity.HIGH,
                            artifact_type="network_connection",
                            data={'line': line}
                        ))

        except Exception as e:
            if self.logger:
                self.logger.error(f"tshark analysis error: {e}")

        return findings

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((c / len(data)) * (freq[c] / len(data) ** 0.5) for c in freq)
        return min(8.0, abs(entropy))


class MemoryAnalyzer:

    def __init__(self, config: ForensicsConfig, logger=None):
        self.config = config
        self.logger = logger
        self.volatility_available = self._check_volatility()

    def _check_volatility(self) -> bool:
        vol_path = Path(self.config.volatility_path) / 'vol.py'
        return vol_path.exists()

    def analyze(self, memory_dump_path: str, evidence_id: str) -> List[ForensicFinding]:
        findings = []

        if not self.volatility_available:
            if self.logger:
                self.logger.warning("Volatility not available, limited memory analysis")
            return findings

        plugins = [
            ('windows.psscan', 'Process Scan', EvidenceSeverity.INFO),
            ('windows.netscan', 'Network Connections', EvidenceSeverity.MEDIUM),
            ('windows.cmdline', 'Command Line', EvidenceSeverity.HIGH),
            ('windows.malfind', 'Malware Detection', EvidenceSeverity.CRITICAL),
            ('windows.dlllist', 'Loaded DLLs', EvidenceSeverity.MEDIUM),
            ('windows.handles', 'Open Handles', EvidenceSeverity.INFO),
            ('windows.svcscan', 'Services', EvidenceSeverity.MEDIUM),
        ]

        for plugin, name, severity in plugins:
            try:
                cmd = ['python3', str(Path(self.config.volatility_path) / 'vol.py'),
                       '-f', memory_dump_path, plugin]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                if result.returncode == 0 and result.stdout.strip():
                    suspicious = self._analyze_plugin_output(plugin, result.stdout)

                    for susp in suspicious:
                        findings.append(ForensicFinding(
                            id=f"MEM-{plugin}-{hash(susp['data']) % 10000}",
                            evidence_id=evidence_id,
                            name=f"{name}: {susp['name']}",
                            description=susp['description'],
                            severity=EvidenceSeverity.HIGH if plugin == 'windows.malfind' else severity,
                            artifact_type=plugin,
                            data=susp['data'],
                            mitre_tactics=susp.get('tactics', []),
                            mitre_techniques=susp.get('techniques', [])
                        ))

                    findings.append(ForensicFinding(
                        id=f"MEM-{plugin}-SUMMARY-{evidence_id[:8]}",
                        evidence_id=evidence_id,
                        name=f"{name} Summary",
                        description=f"Plugin {plugin} executed successfully",
                        severity=severity,
                        artifact_type=plugin,
                        data={'output_preview': result.stdout[:500]}
                    ))

            except subprocess.TimeoutExpired:
                if self.logger:
                    self.logger.warning(f"Timeout running {plugin}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error running {plugin}: {e}")

        return findings

    def _analyze_plugin_output(self, plugin: str, output: str) -> List[Dict]:
        suspicious = []

        if plugin == 'windows.psscan':
            suspicious_names = ['mimikatz', 'procdump', 'psexec', 'nc.exe', 'netcat', 'powershell', 'cmd.exe']
            for line in output.split('\n'):
                for name in suspicious_names:
                    if name.lower() in line.lower():
                        suspicious.append({
                            'name': f'Suspicious process: {name}',
                            'description': f'Found potentially malicious process',
                            'data': {'line': line.strip()},
                            'tactics': ['Execution'],
                            'techniques': ['T1059']
                        })

        elif plugin == 'windows.netscan':
            suspicious_ports = ['4444', '5555', '6666', '7777', '8888', '1337', '31337']
            for line in output.split('\n'):
                for port in suspicious_ports:
                    if f':{port}' in line:
                        suspicious.append({
                            'name': f'Suspicious connection on port {port}',
                            'description': f'Connection to potentially malicious port',
                            'data': {'line': line.strip()},
                            'tactics': ['Command and Control'],
                            'techniques': ['T1071']
                        })

        elif plugin == 'windows.cmdline':
            suspicious_cmds = ['-enc', '-encodedcommand', 'iex', 'invoke-', 'downloadstring', 'reflection']
            for line in output.split('\n'):
                for cmd in suspicious_cmds:
                    if cmd.lower() in line.lower():
                        suspicious.append({
                            'name': f'Suspicious command line',
                            'description': f'Found suspicious command: {cmd}',
                            'data': {'line': line.strip()},
                            'tactics': ['Execution'],
                            'techniques': ['T1059.001']
                        })

        elif plugin == 'windows.malfind':
            if 'VAD' in output and 'PAGE_EXECUTE' in output:
                suspicious.append({
                    'name': 'Potential code injection',
                    'description': 'Malfind detected executable memory with suspicious characteristics',
                    'data': {'output': output[:500]},
                    'tactics': ['Defense Evasion', 'Privilege Escalation'],
                    'techniques': ['T1055']
                })

        return suspicious


class LogAnalyzer:

    def __init__(self, config: ForensicsConfig, logger=None):
        self.config = config
        self.logger = logger
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> List[Dict]:
        return [
            {'pattern': r'Failed password for (?:invalid user )?(\S+) from (\S+) port',
             'name': 'SSH Failed Login', 'severity': EvidenceSeverity.MEDIUM,
             'tactics': ['Credential Access'], 'techniques': ['T1110']},
            {'pattern': r'Accepted password for (\S+) from (\S+)',
             'name': 'SSH Successful Login', 'severity': EvidenceSeverity.INFO},

            {'pattern': r'(SELECT|UNION|INSERT|UPDATE|DELETE).*(FROM|INTO).*[\'\"]',
             'name': 'Potential SQL Injection', 'severity': EvidenceSeverity.CRITICAL,
             'tactics': ['Initial Access'], 'techniques': ['T1190']},
            {'pattern': r'<(script|iframe|img)[^>]*>',
             'name': 'Potential XSS', 'severity': EvidenceSeverity.HIGH,
             'tactics': ['Initial Access'], 'techniques': ['T1189']},
            {'pattern': r'\.\./\.\./|/etc/passwd|cmd\.exe|powershell',
             'name': 'Path Traversal / Command Injection', 'severity': EvidenceSeverity.CRITICAL,
             'tactics': ['Initial Access'], 'techniques': ['T1190']},

            {'pattern': r'EventID[=:]?\s*4625',
             'name': 'Windows Failed Login', 'severity': EvidenceSeverity.MEDIUM,
             'tactics': ['Credential Access'], 'techniques': ['T1110']},
            {'pattern': r'EventID[=:]?\s*4688.*(cmd|powershell|wscript|cscript)',
             'name': 'Suspicious Process Creation', 'severity': EvidenceSeverity.HIGH,
             'tactics': ['Execution'], 'techniques': ['T1059']},
            {'pattern': r'EventID[=:]?\s*1102',
             'name': 'Audit Log Cleared', 'severity': EvidenceSeverity.CRITICAL,
             'tactics': ['Defense Evasion'], 'techniques': ['T1070']},
        ]

    def analyze(self, log_path: str, evidence_id: str, log_type: str = 'auto') -> List[ForensicFinding]:
        findings = []

        if log_type == 'auto':
            log_type = self._detect_log_type(log_path)

        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

                if len(lines) > 100000:
                    lines = lines[:50000] + lines[-50000:]

                for line_num, line in enumerate(lines, 1):
                    for pattern_info in self.patterns:
                        if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                            findings.append(ForensicFinding(
                                id=f"LOG-{hash(line) % 100000:05d}",
                                evidence_id=evidence_id,
                                name=pattern_info['name'],
                                description=f"Found in {log_type} log",
                                severity=pattern_info['severity'],
                                artifact_type=f"log_{log_type}",
                                source_file=log_path,
                                source_line=line_num,
                                data={'line': line.strip()[:500]},
                                mitre_tactics=pattern_info.get('tactics', []),
                                mitre_techniques=pattern_info.get('techniques', [])
                            ))
        except Exception as e:
            if self.logger:
                self.logger.error(f"Log analysis error: {e}")

        return findings

    def _detect_log_type(self, log_path: str) -> str:
        path_lower = log_path.lower()

        if 'auth.log' in path_lower or 'secure' in path_lower:
            return 'auth'
        elif 'access.log' in path_lower or 'access_log' in path_lower:
            return 'web_access'
        elif 'error.log' in path_lower or 'error_log' in path_lower:
            return 'web_error'
        elif 'syslog' in path_lower or 'messages' in path_lower:
            return 'syslog'
        elif '.evtx' in path_lower:
            return 'windows_event'
        else:
            return 'generic'


class TimelineBuilder:

    def __init__(self, config: ForensicsConfig, logger=None):
        self.config = config
        self.logger = logger

    def build_timeline(self, findings: List[ForensicFinding]) -> List[Dict]:
        timeline = []

        for f in findings:
            if f.timestamp:
                timeline.append({
                    'timestamp': f.timestamp,
                    'datetime': datetime.fromtimestamp(f.timestamp).isoformat() if f.timestamp else None,
                    'finding_id': f.id,
                    'name': f.name,
                    'description': f.description,
                    'severity': f.severity.value,
                    'artifact_type': f.artifact_type,
                    'source_file': f.source_file,
                    'mitre_tactics': f.mitre_tactics,
                    'mitre_techniques': f.mitre_techniques
                })

        timeline.sort(key=lambda x: x['timestamp'] if x['timestamp'] else 0)

        return timeline

    def build_attack_chain(self, timeline: List[Dict]) -> List[Dict]:
        chain = []
        current_stage = None
        stage_events = []

        kill_chain_order = [
            'Reconnaissance',
            'Weaponization',
            'Delivery',
            'Exploitation',
            'Installation',
            'Command and Control',
            'Actions on Objectives'
        ]

        for event in timeline:
            stage = self._determine_stage(event)

            if stage != current_stage:
                if stage_events:
                    chain.append({
                        'stage': current_stage,
                        'events': stage_events,
                        'event_count': len(stage_events)
                    })
                current_stage = stage
                stage_events = []

            stage_events.append(event)

        if stage_events:
            chain.append({
                'stage': current_stage,
                'events': stage_events,
                'event_count': len(stage_events)
            })

        return chain

    def _determine_stage(self, event: Dict) -> str:
        tactics = event.get('mitre_tactics', [])

        if 'Reconnaissance' in tactics or 'Discovery' in tactics:
            return 'Reconnaissance'
        elif 'Initial Access' in tactics:
            return 'Delivery'
        elif 'Execution' in tactics:
            return 'Exploitation'
        elif 'Persistence' in tactics or 'Privilege Escalation' in tactics:
            return 'Installation'
        elif 'Command and Control' in tactics:
            return 'Command and Control'
        elif 'Exfiltration' in tactics or 'Impact' in tactics:
            return 'Actions on Objectives'
        elif 'Credential Access' in tactics:
            return 'Exploitation'
        elif 'Lateral Movement' in tactics:
            return 'Actions on Objectives'
        else:
            return 'Unknown'


class ForensicsEngine:

    def __init__(self, config: ForensicsConfig = None, logger=None):
        self.config = config or ForensicsConfig()
        self.logger = logger

        self.pcap_analyzer = PCAPAnalyzer(self.config, logger)
        self.memory_analyzer = MemoryAnalyzer(self.config, logger)
        self.log_analyzer = LogAnalyzer(self.config, logger)
        self.timeline_builder = TimelineBuilder(self.config, logger)

        self.evidence: Dict[str, Evidence] = {}
        self.findings: Dict[str, ForensicFinding] = {}
        self.cases: Dict[str, Dict] = {}

        self.stats = {
            'total_evidence': 0,
            'total_findings': 0,
            'total_cases': 0,
            'critical_findings': 0
        }

        self._lock = threading.RLock()
        self._running = False

        self._init_dirs()
        self._load_cases()

    def _init_dirs(self):
        Path(self.config.evidence_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.cases_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.reports_dir).mkdir(parents=True, exist_ok=True)

    def _load_cases(self):
        cases_dir = Path(self.config.cases_dir)
        for case_file in cases_dir.glob('*.json'):
            try:
                with open(case_file, 'r') as f:
                    case = json.load(f)
                    self.cases[case['id']] = case
                    self.stats['total_cases'] += 1
            except:
                pass

    def start(self):
        self._running = True
        if self.logger:
            self.logger.info("🚀 Digital Forensics Engine started")

    def stop(self):
        self._running = False
        if self.logger:
            self.logger.info("🛑 Digital Forensics Engine stopped")

    def create_case(self, name: str, description: str = "", investigator: str = "SHARD") -> str:
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{hash(name) % 10000:04d}"

        case = {
            'id': case_id,
            'name': name,
            'description': description,
            'investigator': investigator,
            'created_at': time.time(),
            'status': 'open',
            'evidence_ids': [],
            'finding_ids': [],
            'tags': []
        }

        with self._lock:
            self.cases[case_id] = case
            self.stats['total_cases'] += 1

        self._save_case(case_id)

        if self.logger:
            self.logger.info(f"📁 Created case: {case_id} - {name}")

        return case_id

    def _save_case(self, case_id: str):
        case = self.cases.get(case_id)
        if case:
            case_file = Path(self.config.cases_dir) / f"{case_id}.json"
            with open(case_file, 'w') as f:
                json.dump(case, f, indent=2)

    def add_evidence(self, case_id: str, evidence_type: EvidenceType, source: str,
                     file_path: str, notes: str = "") -> str:
        if case_id not in self.cases:
            raise ValueError(f"Case {case_id} not found")

        hash_md5 = None
        hash_sha256 = None
        size_bytes = 0

        try:
            size_bytes = os.path.getsize(file_path)

            if size_bytes < self.config.max_file_size_mb * 1024 * 1024:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    hash_md5 = hashlib.md5(data).hexdigest()
                    hash_sha256 = hashlib.sha256(data).hexdigest()
        except:
            pass

        evidence_id = f"EVD-{datetime.now().strftime('%Y%m%d')}-{hash(file_path) % 100000:05d}"

        evidence = Evidence(
            id=evidence_id,
            case_id=case_id,
            type=evidence_type,
            source=source,
            path=file_path,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            size_bytes=size_bytes,
            notes=notes
        )

        evidence.chain_of_custody.append({
            'timestamp': time.time(),
            'action': 'collected',
            'by': 'SHARD',
            'notes': 'Evidence added to case'
        })

        with self._lock:
            self.evidence[evidence_id] = evidence
            self.cases[case_id]['evidence_ids'].append(evidence_id)
            self.stats['total_evidence'] += 1

        self._save_case(case_id)

        if self.logger:
            self.logger.info(f"🔍 Evidence {evidence_id} added to case {case_id}: {evidence_type.value}")

        if self.config.auto_analyze_alerts:
            self.analyze_evidence(evidence_id)

        return evidence_id

    def analyze_evidence(self, evidence_id: str) -> List[str]:
        evidence = self.evidence.get(evidence_id)
        if not evidence:
            return []

        findings = []

        if evidence.type == EvidenceType.PCAP:
            findings = self.pcap_analyzer.analyze(evidence.path, evidence_id)
        elif evidence.type == EvidenceType.MEMORY_DUMP:
            findings = self.memory_analyzer.analyze(evidence.path, evidence_id)
        elif evidence.type == EvidenceType.LOG_FILE:
            findings = self.log_analyzer.analyze(evidence.path, evidence_id)

        finding_ids = []
        for f in findings:
            with self._lock:
                self.findings[f.id] = f
                self.cases[evidence.case_id]['finding_ids'].append(f.id)
                self.stats['total_findings'] += 1
                if f.severity == EvidenceSeverity.CRITICAL:
                    self.stats['critical_findings'] += 1
            finding_ids.append(f.id)

        if finding_ids:
            self._save_case(evidence.case_id)

            if self.logger:
                self.logger.info(f"🔍 Evidence {evidence_id} analyzed: {len(findings)} findings")

        return finding_ids

    def get_case_timeline(self, case_id: str) -> List[Dict]:
        case = self.cases.get(case_id)
        if not case:
            return []

        case_findings = []
        for fid in case['finding_ids']:
            if fid in self.findings:
                case_findings.append(self.findings[fid])

        return self.timeline_builder.build_timeline(case_findings)

    def get_case_attack_chain(self, case_id: str) -> List[Dict]:
        timeline = self.get_case_timeline(case_id)
        return self.timeline_builder.build_attack_chain(timeline)

    def generate_report(self, case_id: str) -> Dict:
        case = self.cases.get(case_id)
        if not case:
            return {'error': 'Case not found'}

        timeline = self.get_case_timeline(case_id)
        attack_chain = self.get_case_attack_chain(case_id)

        findings_by_severity = defaultdict(int)
        findings_by_type = defaultdict(int)
        iocs = []

        for fid in case['finding_ids']:
            if fid in self.findings:
                f = self.findings[fid]
                findings_by_severity[f.severity.value] += 1
                findings_by_type[f.artifact_type] += 1
                iocs.extend(f.iocs)

        evidence_list = []
        for eid in case['evidence_ids']:
            if eid in self.evidence:
                e = self.evidence[eid]
                evidence_list.append({
                    'id': e.id,
                    'type': e.type.value,
                    'source': e.source,
                    'hash_md5': e.hash_md5,
                    'size_mb': round(e.size_bytes / 1024 / 1024, 2) if e.size_bytes else 0
                })

        report = {
            'case': {
                'id': case['id'],
                'name': case['name'],
                'description': case['description'],
                'investigator': case['investigator'],
                'created_at': datetime.fromtimestamp(case['created_at']).isoformat(),
                'status': case['status']
            },
            'summary': {
                'total_evidence': len(evidence_list),
                'total_findings': len(case['finding_ids']),
                'findings_by_severity': dict(findings_by_severity),
                'findings_by_type': dict(findings_by_type),
                'iocs': iocs[:50]
            },
            'evidence': evidence_list,
            'timeline': timeline[:100],
            'attack_chain': attack_chain,
            'critical_findings': [
                {
                    'id': f.id,
                    'name': f.name,
                    'description': f.description,
                    'timestamp': datetime.fromtimestamp(f.timestamp).isoformat() if f.timestamp else None,
                    'mitre_tactics': f.mitre_tactics,
                    'mitre_techniques': f.mitre_techniques
                }
                for fid in case['finding_ids'] if fid in self.findings
                for f in [self.findings[fid]] if f.severity == EvidenceSeverity.CRITICAL
            ]
        }

        if self.config.auto_generate_report:
            report_path = Path(self.config.reports_dir) / f"{case_id}_report.json"
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)

            html_report = self._generate_html_report(report)
            html_path = Path(self.config.reports_dir) / f"{case_id}_report.html"
            with open(html_path, 'w') as f:
                f.write(html_report)

        return report

    def _generate_html_report(self, report: Dict) -> str:
        case = report['case']
        summary = report['summary']

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SHARD Forensics Report - {case['id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background:
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        h1 {{ color:
        h2 {{ color:
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .card {{ padding: 20px; border-radius: 10px; color: white; text-align: center; }}
        .critical {{ background:
        .high {{ background:
        .medium {{ background:
        .low {{ background:
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid
        th {{ background:
        .timeline {{ margin: 20px 0; }}
        .timeline-event {{ padding: 10px; margin: 5px 0; border-left: 4px solid; background:
        .timeline-event.critical {{ border-color:
        .timeline-event.high {{ border-color:
        .timeline-event.medium {{ border-color:
        .timeline-event.low {{ border-color:
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SHARD Digital Forensics Report</h1>

        <p><strong>Case ID:</strong> {case['id']}</p>
        <p><strong>Case Name:</strong> {case['name']}</p>
        <p><strong>Investigator:</strong> {case['investigator']}</p>
        <p><strong>Created:</strong> {case['created_at']}</p>
        <p><strong>Status:</strong> {case['status']}</p>

        <div class="summary">
            <div class="card">Total Evidence<br><h2>{summary['total_evidence']}</h2></div>
            <div class="card">Total Findings<br><h2>{summary['total_findings']}</h2></div>
            <div class="card critical">Critical<br><h2>{summary['findings_by_severity'].get('CRITICAL', 0)}</h2></div>
            <div class="card high">High<br><h2>{summary['findings_by_severity'].get('HIGH', 0)}</h2></div>
        </div>

        <h2>Evidence</h2>
        <table>
            <tr><th>ID</th><th>Type</th><th>Source</th><th>Size (MB)</th><th>MD5</th></tr>
"""

        for e in report['evidence']:
            html += f"<tr><td>{e['id']}</td><td>{e['type']}</td><td>{e['source'][:50]}</td><td>{e['size_mb']}</td><td>{e['hash_md5'][:16] if e['hash_md5'] else 'N/A'}</td></tr>"

        html += """
        </table>

        <h2>Critical Findings</h2>
"""

        for f in report['critical_findings']:
            html += f"""
        <div class="timeline-event critical">
            <strong>{f['name']}</strong>
            <p>{f['description']}</p>
            <small>MITRE: {', '.join(f['mitre_tactics'][:2])} / {', '.join(f['mitre_techniques'][:2])}</small>
        </div>
"""

        html += """
        <h2>Timeline</h2>
        <div class="timeline">
"""

        for event in report['timeline'][:50]:
            severity_class = event['severity'].lower()
            html += f"""
            <div class="timeline-event {severity_class}">
                <strong>{event['datetime']}</strong> - {event['name']}
                <br><small>{event['description'][:100]}</small>
            </div>
"""

        html += """
        </div>
        <hr>
        <p style="color:
    </div>
</body>
</html>
"""
        return html

    def get_stats(self) -> Dict:
        with self._lock:
            return dict(self.stats)

    def list_cases(self) -> List[Dict]:
        return [
            {
                'id': c['id'],
                'name': c['name'],
                'status': c['status'],
                'created_at': datetime.fromtimestamp(c['created_at']).isoformat(),
                'evidence_count': len(c['evidence_ids']),
                'findings_count': len(c['finding_ids'])
            }
            for c in self.cases.values()
        ]


class ShardForensicsIntegration:

    def __init__(self, config: Dict = None):
        self.config = ForensicsConfig()
        self.engine: Optional[ForensicsEngine] = None
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger):
        self.event_bus = event_bus
        self.logger = logger
        self.engine = ForensicsEngine(self.config, logger)

        if event_bus:
            event_bus.subscribe('alert.detected', self.on_alert)
            event_bus.subscribe('forensics.analyze', self.on_analyze_request)

    def start(self):
        if self.engine:
            self.engine.start()

        if self.logger:
            self.logger.info("🚀 Digital Forensics запущена")

    def stop(self):
        if self.engine:
            self.engine.stop()

    def on_alert(self, alert: Dict):
        if not self.config.auto_analyze_alerts:
            return

        severity = alert.get('severity', 'LOW')
        if severity not in ['CRITICAL', 'HIGH']:
            return

        case_name = f"Alert: {alert.get('attack_type', 'Unknown')} from {alert.get('src_ip', 'unknown')}"
        case_id = self.engine.create_case(
            name=case_name,
            description=alert.get('explanation', 'Auto-created from alert'),
            investigator="SHARD-Auto"
        )

        if self.logger:
            self.logger.info(f"📁 Auto-created case {case_id} for alert")

        if self.event_bus:
            self.event_bus.publish('forensics.case.created', {
                'case_id': case_id,
                'alert': alert
            })

    def on_analyze_request(self, data: Dict):
        evidence_path = data.get('path')
        evidence_type = data.get('type', 'auto')
        case_id = data.get('case_id')

        if not case_id:
            case_id = self.engine.create_case(
                name=f"Manual Analysis {datetime.now().strftime('%Y%m%d-%H%M%S')}",
                description="Manual analysis request"
            )

        if evidence_type == 'auto':
            ext = Path(evidence_path).suffix.lower()
            if ext in ['.pcap', '.pcapng', '.cap']:
                evidence_type = EvidenceType.PCAP
            elif ext in ['.mem', '.dmp', '.raw']:
                evidence_type = EvidenceType.MEMORY_DUMP
            elif ext in ['.log', '.txt']:
                evidence_type = EvidenceType.LOG_FILE
            else:
                evidence_type = EvidenceType.LOG_FILE
        else:
            evidence_type = EvidenceType(evidence_type)

        evidence_id = self.engine.add_evidence(
            case_id=case_id,
            evidence_type=evidence_type,
            source=data.get('source', 'manual'),
            file_path=evidence_path,
            notes=data.get('notes', '')
        )

        finding_ids = self.engine.analyze_evidence(evidence_id)

        if self.event_bus:
            self.event_bus.publish('forensics.analysis.completed', {
                'case_id': case_id,
                'evidence_id': evidence_id,
                'finding_ids': finding_ids,
                'request_id': data.get('request_id')
            })

    def create_case(self, name: str, description: str = "") -> str:
        if self.engine:
            return self.engine.create_case(name, description)
        return ""

    def add_evidence(self, case_id: str, evidence_type: str, source: str, file_path: str) -> str:
        if self.engine:
            return self.engine.add_evidence(
                case_id, EvidenceType(evidence_type), source, file_path
            )
        return ""

    def get_report(self, case_id: str) -> Dict:
        if self.engine:
            return self.engine.generate_report(case_id)
        return {}

    def get_stats(self) -> Dict:
        if self.engine:
            return self.engine.get_stats()
        return {}

    def list_cases(self) -> List[Dict]:
        if self.engine:
            return self.engine.list_cases()
        return []


def test_forensics():
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ DIGITAL FORENSICS")
    print("=" * 60)

    config = ForensicsConfig()
    engine = ForensicsEngine(config)
    engine.start()

    print("\n📝 Тест 1: Создание дела")
    case_id = engine.create_case(
        name="Test Investigation",
        description="Test case for forensics module",
        investigator="Tester"
    )
    print(f"   Case created: {case_id}")

    print("\n📝 Тест 2: Статистика")
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n📝 Тест 3: Список дел")
    cases = engine.list_cases()
    for case in cases:
        print(f"   - {case['id']}: {case['name']} ({case['status']})")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_forensics()
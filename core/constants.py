#!/usr/bin/env python3
"""Shared constants and types for SHARD modules (no circular imports)"""
from enum import Enum

class AttackType(Enum):
    NORMAL = "Normal"
    DOS = "DoS"
    DDOS = "DDoS"
    BRUTE_FORCE = "Brute Force"
    WEB_ATTACK = "Web Attack"
    BOTNET = "Botnet"
    PORT_SCAN = "Port Scan"
    C2_BEACON = "C2 Beacon"
    DNS_TUNNEL = "DNS Tunnel"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    PATH_TRAVERSAL = "Path Traversal"
    CMD_INJECTION = "Command Injection"
    LATERAL_MOVEMENT = "Lateral Movement"
    DATA_EXFILTRATION = "Data Exfiltration"
    PHISHING = "Phishing"
    MALWARE = "Malware"
    UNKNOWN = "Unknown"

class AlertSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DNSThresholds:
    LONG_QUERY = 52
    VERY_LONG_QUERY = 100
    HIGH_ENTROPY = 3.5
    VERY_HIGH_ENTROPY = 4.0
    FREQUENT_QUERIES_PER_MIN = 30
    VERY_FREQUENT_QUERIES_PER_MIN = 60
    MANY_SUBDOMAINS = 50
    MANY_DOTS = 5
    CONSTANT_LENGTH_VARIANCE = 10
    LARGE_DNS_PACKET = 512
    VERY_LARGE_DNS_PACKET = 1000
    EXTREMELY_LARGE_DNS_PACKET = 2000

class ExfilThresholds:
    SINGLE_DST_CRITICAL = 50_000_000
    SINGLE_DST_HIGH = 20_000_000
    SINGLE_DST_MEDIUM = 5_000_000
    TOTAL_CRITICAL = 200_000_000
    TOTAL_HIGH = 100_000_000
    CONNECTIONS_FLOOD = 100
    CONNECTIONS_HIGH = 50
    ASYMMETRIC_RATIO = 10
    LARGE_PACKET = 10000
    MANY_DESTINATIONS = 10
    TIME_WINDOW_5MIN = 300
    TIME_WINDOW_1MIN = 60

class WAFThresholds:
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60
    MAX_BUFFER_SIZE = 200
    CLEANUP_INTERVAL = 5

class BeaconingThresholds:
    BEACON_SCORE_THRESHOLD = 0.7
    MIN_SAMPLES = 5
    CV_THRESHOLD = 0.1

class MLThresholds:
    CONFIDENCE_THRESHOLD = 0.7
    ANOMALY_SCORE_THRESHOLD = -0.2
    RETRAIN_MIN_SAMPLES = 100

# Глобальные переменные для совместимости
try:
    import scapy.all as scapy_all
except ImportError:
    scapy_all = None

try:
    import shap
    shap_module = shap
except ImportError:
    shap_module = None

try:
    import xgboost
    xgboost_module = xgboost
except ImportError:
    xgboost_module = None

try:
    import sklearn.ensemble
    sklearn_ensemble = sklearn.ensemble
except ImportError:
    sklearn_ensemble = None

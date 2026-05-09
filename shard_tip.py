#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SHARD Threat Intelligence Platform (TIP)
Сбор, агрегация, обогащение и обмен индикаторами компрометации (IOC)
Поддержка STIX 2.1, TAXII 2.1, MISP, интеграция с внешними фидами

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import re
import json
import time
import threading
import hashlib
import sqlite3
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import yaml


# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

class IOCType(Enum):
    """Типы индикаторов компрометации"""
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    URI = "uri"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA512 = "hash_sha512"
    EMAIL = "email"
    FILENAME = "filename"
    FILE_PATH = "file_path"
    REGISTRY = "registry"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CVE = "cve"
    YARA_RULE = "yara_rule"
    SNORT_RULE = "snort_rule"
    SURICATA_RULE = "suricata_rule"
    ASN = "asn"
    CIDR = "cidr"
    X509_FINGERPRINT = "x509_fingerprint"
    JA3 = "ja3"
    JA3S = "ja3s"


class IOCSeverity(Enum):
    """Серьёзность индикатора"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IOCStatus(Enum):
    """Статус индикатора"""
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    PENDING = "PENDING"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class TLPMarking(Enum):
    """Traffic Light Protocol маркировка"""
    RED = "RED"  # Только для указанных получателей
    AMBER = "AMBER"  # Ограниченное распространение
    GREEN = "GREEN"  # Распространение в сообществе
    WHITE = "WHITE"  # Без ограничений
    CLEAR = "CLEAR"  # Публичная информация


class ConfidenceLevel(Enum):
    """Уровень уверенности"""
    HIGH = 100
    MEDIUM = 75
    LOW = 50
    UNKNOWN = 25
    NONE = 0


@dataclass
class TIPConfig:
    """Конфигурация Threat Intelligence Platform"""

    # База данных
    db_path: str = "./data/tip/iocs.db"

    # Внешние фиды
    feeds: List[Dict] = field(default_factory=lambda: [
        {'name': 'AlienVault OTX', 'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed', 'type': 'otx',
         'enabled': True},
        {'name': 'Abuse.ch URLhaus', 'url': 'https://urlhaus.abuse.ch/downloads/csv/', 'type': 'csv', 'enabled': True},
        {'name': 'Abuse.ch Feodo', 'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', 'type': 'csv',
         'enabled': True},
        {'name': 'Abuse.ch SSL Blacklist', 'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', 'type': 'csv',
         'enabled': True},
        {'name': 'Tor Exit Nodes', 'url': 'https://check.torproject.org/torbulkexitlist', 'type': 'list',
         'enabled': True},
        {'name': 'Emerging Threats', 'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
         'type': 'list', 'enabled': True},
        {'name': 'Spamhaus DROP', 'url': 'https://www.spamhaus.org/drop/drop.txt', 'type': 'list', 'enabled': True},
        {'name': 'Spamhaus EDROP', 'url': 'https://www.spamhaus.org/drop/edrop.txt', 'type': 'list', 'enabled': True},
    ])

    # TAXII серверы
    taxii_servers: List[Dict] = field(default_factory=lambda: [
        {'name': 'MITRE ATT&CK TAXII', 'url': 'https://cti-taxii.mitre.org/taxii/',
         'collections': ['95ecc380-afe9-11e4-9b6c-751b66dd541e'], 'enabled': True},
    ])

    # MISP интеграция
    misp_enabled: bool = False
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_ssl: bool = False

    # STIX/TAXII
    stix_export_enabled: bool = True
    taxii_server_enabled: bool = False
    taxii_server_port: int = 8443

    # Обновление
    update_interval_hours: int = 6
    max_iocs_per_feed: int = 10000

    # Кэширование
    cache_ttl: int = 3600
    max_cache_size: int = 100000

    # Автоматизация
    auto_enrich: bool = True
    auto_share: bool = False
    confidence_threshold: int = 50


@dataclass
class Indicator:
    """Индикатор компрометации (IOC)"""
    id: str
    type: IOCType
    value: str
    severity: IOCSeverity = IOCSeverity.MEDIUM
    confidence: int = 50
    status: IOCStatus = IOCStatus.ACTIVE
    tlp: TLPMarking = TLPMarking.AMBER
    source: str = "SHARD"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    expiration: Optional[float] = None
    related_iocs: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    malware_family: Optional[str] = None
    enrichment: Dict[str, Any] = field(default_factory=dict)
    sightings: int = 1
    false_positives: int = 0


@dataclass
class ThreatReport:
    """Отчёт об угрозе"""
    id: str
    name: str
    description: str
    author: str
    created_at: float = field(default_factory=time.time)
    modified_at: float = field(default_factory=time.time)
    tlp: TLPMarking = TLPMarking.AMBER
    severity: IOCSeverity = IOCSeverity.MEDIUM
    tags: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_stix: Optional[Dict] = None


# ============================================================
# БАЗА ДАННЫХ IOC
# ============================================================

class IOCDatabase:
    """База данных индикаторов компрометации"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self):
        """Инициализация базы данных"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')

            # Таблица IOC
            conn.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    severity TEXT DEFAULT 'MEDIUM',
                    confidence INTEGER DEFAULT 50,
                    status TEXT DEFAULT 'ACTIVE',
                    tlp TEXT DEFAULT 'AMBER',
                    source TEXT DEFAULT 'SHARD',
                    tags TEXT,
                    description TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    expiration REAL,
                    related_iocs TEXT,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT,
                    threat_actor TEXT,
                    campaign TEXT,
                    malware_family TEXT,
                    enrichment TEXT,
                    sightings INTEGER DEFAULT 1,
                    false_positives INTEGER DEFAULT 0,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')

            # Таблица Threat Reports
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_reports (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    author TEXT,
                    created_at REAL,
                    modified_at REAL,
                    tlp TEXT DEFAULT 'AMBER',
                    severity TEXT DEFAULT 'MEDIUM',
                    tags TEXT,
                    iocs TEXT,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT,
                    threat_actors TEXT,
                    malware_families TEXT,
                    "references" TEXT,
                    raw_stix TEXT
                )
            ''')

            # Таблица Sightings (наблюдения)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sightings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_id TEXT NOT NULL,
                    timestamp REAL,
                    source TEXT,
                    context TEXT,
                    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                )
            ''')

            # Таблица Feed Status
            conn.execute('''
                CREATE TABLE IF NOT EXISTS feed_status (
                    feed_name TEXT PRIMARY KEY,
                    last_fetch REAL,
                    total_fetched INTEGER DEFAULT 0,
                    last_error TEXT,
                    enabled INTEGER DEFAULT 1
                )
            ''')

            # Индексы
            conn.execute('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_iocs_tlp ON iocs(tlp)')

            conn.commit()
            conn.close()

    def upsert_ioc(self, ioc: Indicator) -> bool:
        """Вставка или обновление IOC"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    INSERT OR REPLACE INTO iocs 
                    (id, type, value, severity, confidence, status, tlp, source, tags, description,
                     first_seen, last_seen, expiration, related_iocs, mitre_tactics, mitre_techniques,
                     threat_actor, campaign, malware_family, enrichment, sightings, false_positives, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc.id,
                    ioc.type.value,
                    ioc.value,
                    ioc.severity.value,
                    ioc.confidence,
                    ioc.status.value,
                    ioc.tlp.value,
                    ioc.source,
                    json.dumps(ioc.tags),
                    ioc.description,
                    ioc.first_seen,
                    ioc.last_seen,
                    ioc.expiration,
                    json.dumps(ioc.related_iocs),
                    json.dumps(ioc.mitre_tactics),
                    json.dumps(ioc.mitre_techniques),
                    ioc.threat_actor,
                    ioc.campaign,
                    ioc.malware_family,
                    json.dumps(ioc.enrichment),
                    ioc.sightings,
                    ioc.false_positives,
                    time.time()
                ))
                conn.commit()
                return True
            except Exception as e:
                print(f"Error upserting IOC: {e}")
                return False
            finally:
                conn.close()

    def get_ioc(self, ioc_id: str = None, ioc_type: IOCType = None, value: str = None) -> Optional[Indicator]:
        """Получить IOC по ID или типу/значению"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                if ioc_id:
                    row = conn.execute('SELECT * FROM iocs WHERE id = ?', (ioc_id,)).fetchone()
                elif ioc_type and value:
                    row = conn.execute('SELECT * FROM iocs WHERE type = ? AND value = ?',
                                       (ioc_type.value, value)).fetchone()
                else:
                    return None

                if row:
                    return self._row_to_ioc(row)
                return None
            finally:
                conn.close()

    def search_iocs(self, query: str = None, ioc_type: IOCType = None,
                    severity: IOCSeverity = None, status: IOCStatus = None,
                    source: str = None, tlp: TLPMarking = None,
                    limit: int = 1000) -> List[Indicator]:
        """Поиск IOC"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                sql = 'SELECT * FROM iocs WHERE 1=1'
                params = []

                if query:
                    sql += ' AND (value LIKE ? OR description LIKE ? OR tags LIKE ?)'
                    params.extend([f'%{query}%', f'%{query}%', f'%{query}%'])

                if ioc_type:
                    sql += ' AND type = ?'
                    params.append(ioc_type.value)

                if severity:
                    sql += ' AND severity = ?'
                    params.append(severity.value)

                if status:
                    sql += ' AND status = ?'
                    params.append(status.value)

                if source:
                    sql += ' AND source = ?'
                    params.append(source)

                if tlp:
                    sql += ' AND tlp = ?'
                    params.append(tlp.value)

                sql += ' ORDER BY last_seen DESC LIMIT ?'
                params.append(limit)

                rows = conn.execute(sql, params).fetchall()
                return [self._row_to_ioc(row) for row in rows]
            finally:
                conn.close()

    def _row_to_ioc(self, row) -> Indicator:
        """Конвертация строки в Indicator"""
        return Indicator(
            id=row['id'],
            type=IOCType(row['type']),
            value=row['value'],
            severity=IOCSeverity(row['severity']),
            confidence=row['confidence'],
            status=IOCStatus(row['status']),
            tlp=TLPMarking(row['tlp']),
            source=row['source'],
            tags=json.loads(row['tags'] or '[]'),
            description=row['description'] or '',
            first_seen=row['first_seen'] or time.time(),
            last_seen=row['last_seen'] or time.time(),
            expiration=row['expiration'],
            related_iocs=json.loads(row['related_iocs'] or '[]'),
            mitre_tactics=json.loads(row['mitre_tactics'] or '[]'),
            mitre_techniques=json.loads(row['mitre_techniques'] or '[]'),
            threat_actor=row['threat_actor'],
            campaign=row['campaign'],
            malware_family=row['malware_family'],
            enrichment=json.loads(row['enrichment'] or '{}'),
            sightings=row['sightings'],
            false_positives=row['false_positives']
        )

    def add_sighting(self, ioc_id: str, source: str = "SHARD", context: Dict = None):
        """Добавление наблюдения IOC"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    INSERT INTO sightings (ioc_id, timestamp, source, context)
                    VALUES (?, ?, ?, ?)
                ''', (ioc_id, time.time(), source, json.dumps(context or {})))

                conn.execute('UPDATE iocs SET sightings = sightings + 1, last_seen = ? WHERE id = ?',
                             (time.time(), ioc_id))
                conn.commit()
            finally:
                conn.close()

    def mark_false_positive(self, ioc_id: str):
        """Отметить как ложное срабатывание"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('UPDATE iocs SET false_positives = false_positives + 1, status = ? WHERE id = ?',
                             (IOCStatus.FALSE_POSITIVE.value, ioc_id))
                conn.commit()
            finally:
                conn.close()

    def get_stats(self) -> Dict:
        """Статистика базы данных"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                total = conn.execute('SELECT COUNT(*) FROM iocs').fetchone()[0]
                active = conn.execute('SELECT COUNT(*) FROM iocs WHERE status = ?',
                                      (IOCStatus.ACTIVE.value,)).fetchone()[0]

                by_type = {}
                for t in IOCType:
                    count = conn.execute('SELECT COUNT(*) FROM iocs WHERE type = ?', (t.value,)).fetchone()[0]
                    if count > 0:
                        by_type[t.value] = count

                by_severity = {}
                for s in IOCSeverity:
                    count = conn.execute('SELECT COUNT(*) FROM iocs WHERE severity = ?', (s.value,)).fetchone()[0]
                    if count > 0:
                        by_severity[s.value] = count

                by_source = {}
                sources = conn.execute('SELECT DISTINCT source FROM iocs').fetchall()
                for (src,) in sources:
                    count = conn.execute('SELECT COUNT(*) FROM iocs WHERE source = ?', (src,)).fetchone()[0]
                    by_source[src] = count

                return {
                    'total_iocs': total,
                    'active_iocs': active,
                    'by_type': by_type,
                    'by_severity': by_severity,
                    'by_source': by_source
                }
            finally:
                conn.close()

    def update_feed_status(self, feed_name: str, fetched: int = 0, error: str = None):
        """Обновление статуса фида"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    INSERT OR REPLACE INTO feed_status (feed_name, last_fetch, total_fetched, last_error)
                    VALUES (?, ?, COALESCE((SELECT total_fetched FROM feed_status WHERE feed_name = ?), 0) + ?, ?)
                ''', (feed_name, time.time(), feed_name, fetched, error))
                conn.commit()
            finally:
                conn.close()


# ============================================================
# IOC ENRICHER
# ============================================================

class IOCEnricher:
    """Обогащение индикаторов данными из внешних источников"""

    def __init__(self, config: TIPConfig, logger=None):
        self.config = config
        self.logger = logger
        self.cache: Dict[str, Tuple[float, Dict]] = {}
        self._lock = threading.RLock()

    def enrich(self, ioc: Indicator) -> Indicator:
        """Обогащение индикатора"""
        cache_key = f"{ioc.type.value}:{ioc.value}"

        with self._lock:
            if cache_key in self.cache:
                cached_time, cached_data = self.cache[cache_key]
                if time.time() - cached_time < self.config.cache_ttl:
                    ioc.enrichment.update(cached_data)
                    return ioc

        enrichment = {}

        if ioc.type == IOCType.IP or ioc.type == IOCType.IPV4:
            enrichment.update(self._enrich_ip(ioc.value))
        elif ioc.type == IOCType.DOMAIN:
            enrichment.update(self._enrich_domain(ioc.value))
        elif ioc.type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
            enrichment.update(self._enrich_hash(ioc.value))
        elif ioc.type == IOCType.URL:
            enrichment.update(self._enrich_url(ioc.value))

        ioc.enrichment.update(enrichment)

        with self._lock:
            self.cache[cache_key] = (time.time(), enrichment)
            if len(self.cache) > self.config.max_cache_size:
                # Удаление старых записей
                items = sorted(self.cache.items(), key=lambda x: x[1][0])
                for k, _ in items[:1000]:
                    del self.cache[k]

        return ioc

    def _enrich_ip(self, ip: str) -> Dict:
        """Обогащение IP адреса"""
        enrichment = {}

        # Проверка приватных IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            enrichment['is_private'] = ip_obj.is_private
            enrichment['is_global'] = ip_obj.is_global
        except:
            pass

        # GeoIP (ip-api.com)
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    enrichment['geo'] = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as')
                    }
        except:
            pass

        # AbuseIPDB
        abuse_key = os.environ.get('ABUSEIPDB_KEY', '')
        if abuse_key:
            try:
                headers = {'Key': abuse_key, 'Accept': 'application/json'}
                response = requests.get('https://api.abuseipdb.com/api/v2/check',
                                        params={'ipAddress': ip, 'maxAgeInDays': 90},
                                        headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    enrichment['abuseipdb'] = {
                        'score': data.get('abuseConfidenceScore', 0),
                        'total_reports': data.get('totalReports', 0),
                        'last_reported': data.get('lastReportedAt'),
                        'country': data.get('countryCode'),
                        'isp': data.get('isp'),
                        'usage_type': data.get('usageType'),
                        'domain': data.get('domain')
                    }
            except:
                pass

        return enrichment

    def _enrich_domain(self, domain: str) -> Dict:
        """Обогащение домена"""
        enrichment = {}

        # WHOIS (упрощённо через API)
        try:
            response = requests.get(f'https://api.domainsdb.info/v1/domains/search?domain={domain}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('domains'):
                    enrichment['whois'] = data['domains'][0]
        except:
            pass

        # Разрешение DNS
        try:
            import socket
            ips = []
            for addr in socket.getaddrinfo(domain, 80):
                ips.append(addr[4][0])
            enrichment['resolved_ips'] = list(set(ips))
        except:
            pass

        # SSL сертификат
        try:
            import ssl
            import socket
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                enrichment['ssl_cert'] = {
                    'issuer': dict(cert.get('issuer', [])),
                    'subject': dict(cert.get('subject', [])),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'serial_number': cert.get('serialNumber')
                }
        except:
            pass

        return enrichment

    def _enrich_hash(self, file_hash: str) -> Dict:
        """Обогащение хеша файла"""
        enrichment = {}

        # VirusTotal
        vt_key = os.environ.get('VIRUSTOTAL_KEY', '')
        if vt_key:
            try:
                headers = {'x-apikey': vt_key}
                response = requests.get(f'https://www.virustotal.com/api/v3/files/{file_hash}',
                                        headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    attrs = data.get('data', {}).get('attributes', {})
                    enrichment['virustotal'] = {
                        'detection_ratio': f"{attrs.get('last_analysis_stats', {}).get('malicious', 0)}/{attrs.get('last_analysis_stats', {}).get('total', 0)}",
                        'meaningful_name': attrs.get('meaningful_name'),
                        'type_description': attrs.get('type_description'),
                        'size': attrs.get('size'),
                        'first_submission': attrs.get('first_submission_date'),
                        'last_submission': attrs.get('last_submission_date'),
                        'tags': attrs.get('tags', [])
                    }
            except:
                pass

        return enrichment

    def _enrich_url(self, url: str) -> Dict:
        """Обогащение URL"""
        enrichment = {}

        # Парсинг URL
        try:
            parsed = urlparse(url)
            enrichment['parsed'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'hostname': parsed.hostname,
                'port': parsed.port
            }
        except:
            pass

        # URLhaus
        try:
            response = requests.post('https://urlhaus-api.abuse.ch/v1/url/',
                                     data={'url': url}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    enrichment['urlhaus'] = {
                        'threat': data.get('threat'),
                        'url_status': data.get('url_status'),
                        'tags': data.get('tags', [])
                    }
        except:
            pass

        return enrichment


# ============================================================
# FEED PARSER
# ============================================================

class FeedParser:
    """Парсер внешних фидов threat intelligence"""

    def __init__(self, config: TIPConfig, logger=None):
        self.config = config
        self.logger = logger

    def parse_otx(self, data: Dict) -> List[Indicator]:
        """Парсинг AlienVault OTX"""
        iocs = []

        for pulse in data.get('results', []):
            for indicator in pulse.get('indicators', []):
                ioc_type = indicator.get('type')
                value = indicator.get('indicator')

                if ioc_type and value:
                    try:
                        ioc = Indicator(
                            id=f"OTX-{hash(value)}",
                            type=self._map_otx_type(ioc_type),
                            value=value,
                            severity=IOCSeverity.MEDIUM,
                            confidence=70,
                            source="AlienVault OTX",
                            tags=pulse.get('tags', []),
                            description=pulse.get('description', '')[:500],
                            threat_actor=pulse.get('adversary'),
                            malware_family=next((t for t in pulse.get('tags', []) if 'malware' in t.lower()), None)
                        )
                        iocs.append(ioc)
                    except:
                        pass

        return iocs

    def parse_csv_list(self, data: str, feed_name: str) -> List[Indicator]:
        """Парсинг CSV/списка"""
        iocs = []

        for line in data.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(',')
            if parts:
                value = parts[0].strip()
                if value:
                    ioc_type = self._detect_type(value)
                    if ioc_type:
                        ioc = Indicator(
                            id=f"{feed_name}-{hash(value)}",
                            type=ioc_type,
                            value=value,
                            severity=IOCSeverity.HIGH,
                            confidence=80,
                            source=feed_name
                        )
                        iocs.append(ioc)

        return iocs

    def parse_tor_list(self, data: str) -> List[Indicator]:
        """Парсинг списка Tor exit nodes"""
        iocs = []

        for line in data.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    ipaddress.ip_address(line)
                    ioc = Indicator(
                        id=f"TOR-{hash(line)}",
                        type=IOCType.IP,
                        value=line,
                        severity=IOCSeverity.MEDIUM,
                        confidence=90,
                        source="Tor Exit Nodes",
                        tags=['tor', 'exit-node'],
                        description="Tor exit node"
                    )
                    iocs.append(ioc)
                except:
                    pass

        return iocs

    def _map_otx_type(self, otx_type: str) -> IOCType:
        """Маппинг типов OTX на IOCType"""
        mapping = {
            'IPv4': IOCType.IPV4,
            'IPv6': IOCType.IPV6,
            'domain': IOCType.DOMAIN,
            'hostname': IOCType.DOMAIN,
            'URL': IOCType.URL,
            'FileHash-MD5': IOCType.HASH_MD5,
            'FileHash-SHA1': IOCType.HASH_SHA1,
            'FileHash-SHA256': IOCType.HASH_SHA256,
            'email': IOCType.EMAIL,
            'CVE': IOCType.CVE,
            'YARA': IOCType.YARA_RULE
        }
        return mapping.get(otx_type, IOCType.URL)

    def _detect_type(self, value: str) -> Optional[IOCType]:
        """Определение типа IOC по значению"""
        # IP
        try:
            ipaddress.ip_address(value)
            return IOCType.IP
        except:
            pass

        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', value):
            return IOCType.DOMAIN

        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return IOCType.URL

        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return IOCType.EMAIL

        # MD5
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return IOCType.HASH_MD5

        # SHA1
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return IOCType.HASH_SHA1

        # SHA256
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return IOCType.HASH_SHA256

        # CVE
        if re.match(r'^CVE-\d{4}-\d{4,}$', value, re.IGNORECASE):
            return IOCType.CVE

        return None


# ============================================================
# STIX CONVERTER
# ============================================================

class STIXConverter:
    """Конвертация между STIX 2.1 и внутренним форматом"""

    def to_stix_bundle(self, indicators: List[Indicator]) -> Dict:
        """Конвертация в STIX Bundle"""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": []
        }

        # Добавление Identity (SHARD)
        bundle["objects"].append({
            "type": "identity",
            "id": "identity--shard-enterprise",
            "name": "SHARD Enterprise SIEM",
            "identity_class": "organization",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z"
        })

        for ioc in indicators:
            stix_obj = self._indicator_to_stix(ioc)
            bundle["objects"].append(stix_obj)

        return bundle

    def _indicator_to_stix(self, ioc: Indicator) -> Dict:
        """Конвертация Indicator в STIX Indicator"""
        stix_id = f"indicator--{uuid.uuid4()}"

        pattern = self._to_stix_pattern(ioc)

        valid_from = datetime.fromtimestamp(ioc.first_seen).isoformat() + "Z"

        stix_indicator = {
            "type": "indicator",
            "id": stix_id,
            "spec_version": "2.1",
            "created": valid_from,
            "modified": datetime.fromtimestamp(ioc.last_seen).isoformat() + "Z",
            "name": f"{ioc.type.value.upper()}: {ioc.value}",
            "description": ioc.description or f"Indicator from {ioc.source}",
            "indicator_types": self._to_stix_indicator_types(ioc),
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": valid_from,
            "confidence": ioc.confidence,
            "labels": ioc.tags,
            "created_by_ref": "identity--shard-enterprise",
            "object_marking_refs": [self._to_stix_marking(ioc.tlp)],
            "external_references": [{"source_name": ioc.source}]
        }

        if ioc.kill_chain_phases:
            stix_indicator["kill_chain_phases"] = ioc.kill_chain_phases

        return stix_indicator

    def _to_stix_pattern(self, ioc: Indicator) -> str:
        """Конвертация в STIX pattern"""
        if ioc.type == IOCType.IP or ioc.type == IOCType.IPV4:
            return f"[ipv4-addr:value = '{ioc.value}']"
        elif ioc.type == IOCType.IPV6:
            return f"[ipv6-addr:value = '{ioc.value}']"
        elif ioc.type == IOCType.DOMAIN:
            return f"[domain-name:value = '{ioc.value}']"
        elif ioc.type == IOCType.URL:
            return f"[url:value = '{ioc.value}']"
        elif ioc.type == IOCType.HASH_MD5:
            return f"[file:hashes.MD5 = '{ioc.value}']"
        elif ioc.type == IOCType.HASH_SHA1:
            return f"[file:hashes.'SHA-1' = '{ioc.value}']"
        elif ioc.type == IOCType.HASH_SHA256:
            return f"[file:hashes.'SHA-256' = '{ioc.value}']"
        elif ioc.type == IOCType.EMAIL:
            return f"[email-addr:value = '{ioc.value}']"
        else:
            return f"[artifact:payload_bin = '{ioc.value}']"

    def _to_stix_indicator_types(self, ioc: Indicator) -> List[str]:
        """Определение indicator_types для STIX"""
        types = ["malicious-activity"]

        if ioc.type in [IOCType.IP, IOCType.IPV4, IOCType.IPV6]:
            types.append("anonymization")
        if ioc.severity in [IOCSeverity.CRITICAL, IOCSeverity.HIGH]:
            types.append("benign")
        if "c2" in ioc.tags or "command" in ioc.tags:
            types.append("command-and-control")

        return list(set(types))

    def _to_stix_marking(self, tlp: TLPMarking) -> str:
        """Конвертация TLP в STIX marking"""
        mapping = {
            TLPMarking.RED: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            TLPMarking.AMBER: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            TLPMarking.GREEN: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            TLPMarking.WHITE: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        }
        return mapping.get(tlp, "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9")

    def from_stix_bundle(self, bundle: Dict) -> List[Indicator]:
        """Конвертация из STIX Bundle"""
        indicators = []

        for obj in bundle.get('objects', []):
            if obj.get('type') == 'indicator':
                ioc = self._stix_to_indicator(obj)
                if ioc:
                    indicators.append(ioc)

        return indicators

    def _stix_to_indicator(self, obj: Dict) -> Optional[Indicator]:
        """Конвертация STIX Indicator в Indicator"""
        try:
            pattern = obj.get('pattern', '')

            # Извлечение типа и значения из pattern
            ioc_type = None
            value = None

            if '[ipv4-addr:value' in pattern or '[ipv6-addr:value' in pattern:
                ioc_type = IOCType.IP
            elif '[domain-name:value' in pattern:
                ioc_type = IOCType.DOMAIN
            elif '[url:value' in pattern:
                ioc_type = IOCType.URL
            elif '[file:hashes.MD5' in pattern:
                ioc_type = IOCType.HASH_MD5
            elif "[file:hashes.'SHA-1'" in pattern:
                ioc_type = IOCType.HASH_SHA1
            elif "[file:hashes.'SHA-256'" in pattern:
                ioc_type = IOCType.HASH_SHA256
            elif '[email-addr:value' in pattern:
                ioc_type = IOCType.EMAIL

            if ioc_type is None:
                return None

            # Извлечение значения
            match = re.search(r"=\s*'([^']+)'", pattern)
            if match:
                value = match.group(1)
            else:
                return None

            return Indicator(
                id=f"STIX-{hash(obj['id'])}",
                type=ioc_type,
                value=value,
                confidence=obj.get('confidence', 50),
                source="STIX Import",
                description=obj.get('description', ''),
                tags=obj.get('labels', []),
                first_seen=datetime.fromisoformat(obj.get('created', '').replace('Z', '+00:00')).timestamp(),
                last_seen=datetime.fromisoformat(obj.get('modified', '').replace('Z', '+00:00')).timestamp()
            )
        except:
            return None


# ============================================================
# THREAT INTELLIGENCE PLATFORM ENGINE
# ============================================================

class TIPEngine:
    """
    Основной движок Threat Intelligence Platform
    Управляет сбором, обогащением и распространением IOC
    """

    def __init__(self, config: TIPConfig = None, logger=None):
        self.config = config or TIPConfig()
        self.logger = logger

        self.database = IOCDatabase(self.config.db_path)
        self.enricher = IOCEnricher(self.config, logger)
        self.feed_parser = FeedParser(self.config, logger)
        self.stix_converter = STIXConverter()

        self.stats = {
            'total_fetched': 0,
            'total_enriched': 0,
            'total_shared': 0
        }

        self._lock = threading.RLock()
        self._running = False
        self._update_thread = None

    def start(self):
        """Запуск движка"""
        self._running = True
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()

        if self.logger:
            self.logger.info("🚀 Threat Intelligence Platform started")

    def stop(self):
        """Остановка движка"""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)

        if self.logger:
            self.logger.info("🛑 Threat Intelligence Platform stopped")

    def _update_loop(self):
        """Цикл обновления фидов"""
        while self._running:
            self.fetch_all_feeds()
            time.sleep(self.config.update_interval_hours * 3600)

    def fetch_all_feeds(self) -> int:
        """Загрузка всех включённых фидов"""
        total_fetched = 0

        for feed in self.config.feeds:
            if not feed.get('enabled', True):
                continue

            try:
                fetched = self.fetch_feed(feed)
                total_fetched += fetched
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error fetching feed {feed['name']}: {e}")
                self.database.update_feed_status(feed['name'], error=str(e))

        with self._lock:
            self.stats['total_fetched'] += total_fetched

        if self.logger:
            self.logger.info(f"📥 Fetched {total_fetched} IOCs from feeds")

        return total_fetched

    def fetch_feed(self, feed: Dict) -> int:
        """Загрузка одного фида"""
        response = requests.get(feed['url'], timeout=60, headers={'User-Agent': 'SHARD-TIP/5.0'})

        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")

        iocs = []

        if feed['type'] == 'otx':
            data = response.json()
            iocs = self.feed_parser.parse_otx(data)
        elif feed['type'] == 'csv':
            iocs = self.feed_parser.parse_csv_list(response.text, feed['name'])
        elif feed['type'] == 'list':
            if 'tor' in feed['name'].lower():
                iocs = self.feed_parser.parse_tor_list(response.text)
            else:
                iocs = self.feed_parser.parse_csv_list(response.text, feed['name'])

        # Ограничение количества
        iocs = iocs[:self.config.max_iocs_per_feed]

        # Сохранение в БД
        saved = 0
        for ioc in iocs:
            if self.add_ioc(ioc):
                saved += 1

        self.database.update_feed_status(feed['name'], fetched=saved)

        return saved

    def add_ioc(self, ioc: Indicator, auto_enrich: bool = True) -> bool:
        """Добавление индикатора"""
        # Генерация ID если не задан
        if not ioc.id:
            ioc.id = f"IOC-{ioc.type.value}-{hash(ioc.value) % 1000000:06d}"

        # Проверка существующего
        existing = self.database.get_ioc(ioc_type=ioc.type, value=ioc.value)
        if existing:
            # Обновление sightings
            existing.sightings += 1
            existing.last_seen = time.time()
            return self.database.upsert_ioc(existing)

        # Обогащение
        if auto_enrich and self.config.auto_enrich:
            ioc = self.enricher.enrich(ioc)
            with self._lock:
                self.stats['total_enriched'] += 1

        return self.database.upsert_ioc(ioc)

    def lookup(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[Indicator]:
        """Поиск индикатора"""
        if ioc_type:
            return self.database.get_ioc(ioc_type=ioc_type, value=value)

        # Автоопределение типа
        detected_type = self.feed_parser._detect_type(value)
        if detected_type:
            return self.database.get_ioc(ioc_type=detected_type, value=value)

        return None

    def search(self, query: str, limit: int = 100) -> List[Indicator]:
        """Поиск индикаторов"""
        return self.database.search_iocs(query=query, limit=limit)

    def check_alert(self, alert: Dict) -> List[Indicator]:
        """Проверка алерта на наличие IOC"""
        matched_iocs = []

        # Проверка IP
        src_ip = alert.get('src_ip')
        if src_ip:
            ioc = self.lookup(src_ip, IOCType.IP)
            if ioc:
                matched_iocs.append(ioc)
                self.database.add_sighting(ioc.id, "alert", alert)

        dst_ip = alert.get('dst_ip')
        if dst_ip:
            ioc = self.lookup(dst_ip, IOCType.IP)
            if ioc and ioc not in matched_iocs:
                matched_iocs.append(ioc)
                self.database.add_sighting(ioc.id, "alert", alert)

        # Проверка доменов в alert
        explanation = alert.get('explanation', '')
        domain_pattern = r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+'
        for domain in re.findall(domain_pattern, explanation):
            ioc = self.lookup(domain, IOCType.DOMAIN)
            if ioc and ioc not in matched_iocs:
                matched_iocs.append(ioc)
                self.database.add_sighting(ioc.id, "alert", alert)

        return matched_iocs

    def export_stix(self, ioc_ids: List[str] = None, query: str = None) -> str:
        """Экспорт в STIX формат"""
        if ioc_ids:
            iocs = []
            for ioc_id in ioc_ids:
                ioc = self.database.get_ioc(ioc_id=ioc_id)
                if ioc:
                    iocs.append(ioc)
        elif query:
            iocs = self.search(query, limit=1000)
        else:
            iocs = self.database.search_iocs(status=IOCStatus.ACTIVE, limit=1000)

        bundle = self.stix_converter.to_stix_bundle(iocs)
        return json.dumps(bundle, indent=2)

    def import_stix(self, stix_data: str) -> int:
        """Импорт из STIX"""
        try:
            bundle = json.loads(stix_data)
            iocs = self.stix_converter.from_stix_bundle(bundle)

            imported = 0
            for ioc in iocs:
                if self.add_ioc(ioc, auto_enrich=True):
                    imported += 1

            return imported
        except Exception as e:
            if self.logger:
                self.logger.error(f"STIX import error: {e}")
            return 0

    def mark_false_positive(self, ioc_id: str):
        """Отметить как ложное срабатывание"""
        self.database.mark_false_positive(ioc_id)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        db_stats = self.database.get_stats()
        with self._lock:
            return {**db_stats, **self.stats}

    def get_top_iocs(self, limit: int = 10) -> List[Dict]:
        """Получить топ IOC по sightings"""
        iocs = self.database.search_iocs(status=IOCStatus.ACTIVE, limit=1000)
        iocs.sort(key=lambda x: x.sightings, reverse=True)

        return [
            {
                'id': ioc.id,
                'type': ioc.type.value,
                'value': ioc.value,
                'severity': ioc.severity.value,
                'sightings': ioc.sightings,
                'source': ioc.source,
                'tags': ioc.tags[:5]
            }
            for ioc in iocs[:limit]
        ]


# ============================================================
# ИНТЕГРАЦИЯ С SHARD
# ============================================================

class ShardTIPIntegration:
    """Интеграция Threat Intelligence Platform в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = TIPConfig()
        self.engine: Optional[TIPEngine] = None
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger):
        """Настройка интеграции"""
        self.event_bus = event_bus
        self.logger = logger
        self.engine = TIPEngine(self.config, logger)

        if event_bus:
            event_bus.subscribe('alert.detected', self.on_alert)
            event_bus.subscribe('tip.lookup', self.on_lookup_request)
            event_bus.subscribe('tip.export', self.on_export_request)

    def start(self):
        """Запуск интеграции"""
        if self.engine:
            self.engine.start()

        if self.logger:
            self.logger.info("🚀 Threat Intelligence Platform запущена")

    def stop(self):
        """Остановка интеграции"""
        if self.engine:
            self.engine.stop()

    def on_alert(self, alert: Dict):
        """Обработка алерта - проверка IOC"""
        if not self.engine:
            return

        matched_iocs = self.engine.check_alert(alert)

        if matched_iocs:
            # Обогащение алерта
            alert['threat_intel'] = {
                'iocs': [
                    {
                        'id': ioc.id,
                        'type': ioc.type.value,
                        'value': ioc.value,
                        'severity': ioc.severity.value,
                        'confidence': ioc.confidence,
                        'source': ioc.source,
                        'tags': ioc.tags[:5],
                        'malware_family': ioc.malware_family,
                        'threat_actor': ioc.threat_actor
                    }
                    for ioc in matched_iocs
                ]
            }

            # Повышение score алерта
            max_severity = max(ioc.severity for ioc in matched_iocs)
            if max_severity == IOCSeverity.CRITICAL:
                alert['score'] = min(1.0, alert.get('score', 0) + 0.3)
                alert['severity'] = 'CRITICAL'
            elif max_severity == IOCSeverity.HIGH:
                alert['score'] = min(1.0, alert.get('score', 0) + 0.2)

            if self.logger:
                self.logger.warning(f"🔍 Alert matched {len(matched_iocs)} IOCs")

    def on_lookup_request(self, data: Dict):
        """Обработка запроса lookup"""
        value = data.get('value', '')
        ioc_type = data.get('type')

        if value and self.engine:
            if ioc_type:
                try:
                    ioc_type = IOCType(ioc_type)
                except:
                    ioc_type = None

            ioc = self.engine.lookup(value, ioc_type)

            if self.event_bus:
                self.event_bus.publish('tip.lookup.response', {
                    'value': value,
                    'ioc': {
                        'id': ioc.id,
                        'type': ioc.type.value,
                        'value': ioc.value,
                        'severity': ioc.severity.value,
                        'confidence': ioc.confidence,
                        'source': ioc.source,
                        'sightings': ioc.sightings,
                        'enrichment': ioc.enrichment,
                        'malware_family': ioc.malware_family,
                        'threat_actor': ioc.threat_actor
                    } if ioc else None,
                    'request_id': data.get('request_id')
                })

    def on_export_request(self, data: Dict):
        """Обработка запроса экспорта"""
        format_type = data.get('format', 'stix')
        ioc_ids = data.get('ioc_ids')
        query = data.get('query')

        if self.engine:
            if format_type == 'stix':
                result = self.engine.export_stix(ioc_ids, query)

                if self.event_bus:
                    self.event_bus.publish('tip.export.response', {
                        'format': format_type,
                        'data': result,
                        'request_id': data.get('request_id')
                    })

    def add_ioc(self, ioc_type: str, value: str, severity: str = "MEDIUM",
                tags: List[str] = None, source: str = "manual") -> bool:
        """Добавить IOC вручную"""
        if self.engine:
            try:
                ioc = Indicator(
                    type=IOCType(ioc_type),
                    value=value,
                    severity=IOCSeverity(severity),
                    source=source,
                    tags=tags or []
                )
                return self.engine.add_ioc(ioc)
            except:
                return False
        return False

    def lookup(self, value: str) -> Optional[Dict]:
        """Поиск IOC"""
        if self.engine:
            ioc = self.engine.lookup(value)
            if ioc:
                return {
                    'id': ioc.id,
                    'type': ioc.type.value,
                    'value': ioc.value,
                    'severity': ioc.severity.value,
                    'confidence': ioc.confidence,
                    'source': ioc.source,
                    'sightings': ioc.sightings,
                    'tags': ioc.tags,
                    'malware_family': ioc.malware_family,
                    'threat_actor': ioc.threat_actor
                }
        return None

    def get_stats(self) -> Dict:
        """Получить статистику"""
        if self.engine:
            return self.engine.get_stats()
        return {}

    def fetch_feeds(self) -> int:
        """Принудительная загрузка фидов"""
        if self.engine:
            return self.engine.fetch_all_feeds()
        return 0


# ============================================================
# ТЕСТИРОВАНИЕ
# ============================================================

def test_tip():
    """Тестирование Threat Intelligence Platform"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ THREAT INTELLIGENCE PLATFORM")
    print("=" * 60)

    config = TIPConfig()
    # Отключаем фиды для теста
    config.feeds = []
    config.update_interval_hours = 0

    engine = TIPEngine(config)

    # Тест 1: Добавление IOC
    print("\n📝 Тест 1: Добавление IOC")
    ioc1 = Indicator(
        type=IOCType.IP,
        value="185.142.53.101",
        severity=IOCSeverity.HIGH,
        confidence=85,
        source="test",
        tags=["bruteforce", "ssh"],
        description="SSH brute force source"
    )
    engine.add_ioc(ioc1, auto_enrich=True)

    ioc2 = Indicator(
        type=IOCType.DOMAIN,
        value="malicious-test.com",
        severity=IOCSeverity.CRITICAL,
        source="test",
        tags=["c2", "botnet"]
    )
    engine.add_ioc(ioc2)

    # Тест 2: Lookup
    print("\n📝 Тест 2: Lookup")
    found = engine.lookup("185.142.53.101")
    if found:
        print(
            f"   Found: {found.type.value}:{found.value} (severity: {found.severity.value}, sightings: {found.sightings})")
        if found.enrichment:
            print(f"   Enriched: {list(found.enrichment.keys())}")

    # Тест 3: Поиск
    print("\n📝 Тест 3: Поиск")
    results = engine.search("malicious", limit=10)
    print(f"   Found {len(results)} results")
    for r in results:
        print(f"      - {r.type.value}:{r.value} ({r.severity.value})")

    # Тест 4: Проверка алерта
    print("\n📝 Тест 4: Проверка алерта")
    alert = {
        'src_ip': '185.142.53.101',
        'dst_ip': '10.0.0.5',
        'attack_type': 'Brute Force',
        'explanation': 'Multiple failed SSH logins'
    }
    matched = engine.check_alert(alert)
    print(f"   Matched {len(matched)} IOCs")

    # Тест 5: Экспорт STIX
    print("\n📝 Тест 5: Экспорт STIX")
    stix = engine.export_stix(query="malicious", limit=2)
    print(f"   STIX bundle size: {len(stix)} bytes")

    # Тест 6: Статистика
    print("\n📝 Тест 6: Статистика")
    stats = engine.get_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"   {key}: {len(value)} items")
        else:
            print(f"   {key}: {value}")

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    import uuid

    test_tip()
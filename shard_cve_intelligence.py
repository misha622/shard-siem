#!/usr/bin/env python3

"""
SHARD CVE Intelligence Module
Анализ уязвимостей CVE и сопоставление с инфраструктурой
Аналог CySecBERT для SHARD

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import re
import json
import time
import gzip
import threading
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml
import xml.etree.ElementTree as ET



class CVESeverity(Enum):
    """Уровни серьёзности CVE"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class CVEStatus(Enum):
    """Статус CVE в инфраструктуре"""
    VULNERABLE = "VULNERABLE"
    PATCHED = "PATCHED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


@dataclass
class CVEIntelligenceConfig:
    """Конфигурация CVE Intelligence"""

    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_database_path: str = "./data/cve/cve.db"
    exploit_db_path: str = "./data/cve/exploitdb"

    auto_update: bool = True
    update_interval_hours: int = 24
    max_cves_per_update: int = 2000

    cache_ttl: int = 3600
    max_cache_size: int = 10000

    nvd_api_key: str = ""

    alert_on_cvss: float = 7.0
    critical_cvss: float = 9.0

    scan_installed_software: bool = True
    scan_dependencies: bool = True

    reports_dir: str = "./data/cve/reports/"



@dataclass
class CVE:
    """Модель CVE"""
    cve_id: str
    description: str
    published_date: str
    last_modified_date: str
    cvss_v3_score: Optional[float]
    cvss_v3_vector: Optional[str]
    cvss_v3_severity: str
    cvss_v2_score: Optional[float]
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_links: List[str] = field(default_factory=list)
    patch_available: bool = False
    patch_links: List[str] = field(default_factory=list)

    def get_severity(self) -> CVESeverity:
        """Получить серьёзность"""
        score = self.cvss_v3_score or self.cvss_v2_score or 0
        if score >= 9.0:
            return CVESeverity.CRITICAL
        elif score >= 7.0:
            return CVESeverity.HIGH
        elif score >= 4.0:
            return CVESeverity.MEDIUM
        elif score > 0:
            return CVESeverity.LOW
        return CVESeverity.NONE


@dataclass
class Software:
    """Модель установленного ПО"""
    name: str
    version: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    cpe: Optional[str] = None
    path: Optional[str] = None
    source: str = "unknown"
    last_seen: float = field(default_factory=time.time)


@dataclass
class VulnerabilityMatch:
    """Совпадение CVE с установленным ПО"""
    software: Software
    cve: CVE
    status: CVEStatus = CVEStatus.UNKNOWN
    confidence: float = 1.0
    risk_score: float = 0.0
    matched_by: str = "cpe"
    remediation: Optional[str] = None



class CVEDatabase:
    """Локальная база данных CVE (SQLite)"""

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

            conn.execute('''
                CREATE TABLE IF NOT EXISTS cve (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    published_date TEXT,
                    last_modified_date TEXT,
                    cvss_v3_score REAL,
                    cvss_v3_vector TEXT,
                    cvss_v3_severity TEXT,
                    cvss_v2_score REAL,
                    cwe_ids TEXT,
                    "references" TEXT,
                    affected_products TEXT,
                    exploit_available INTEGER DEFAULT 0,
                    patch_available INTEGER DEFAULT 0,
                    raw_data TEXT,
                    updated_at REAL
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS software (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    cpe TEXT,
                    path TEXT,
                    source TEXT,
                    last_seen REAL,
                    UNIQUE(name, version, path)
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    software_id INTEGER,
                    cve_id TEXT,
                    status TEXT,
                    confidence REAL,
                    risk_score REAL,
                    matched_by TEXT,
                    remediation TEXT,
                    detected_at REAL,
                    FOREIGN KEY (software_id) REFERENCES software(id),
                    FOREIGN KEY (cve_id) REFERENCES cve(cve_id),
                    UNIQUE(software_id, cve_id)
                )
            ''')

            conn.execute('CREATE INDEX IF NOT EXISTS idx_cve_score ON cve(cvss_v3_score)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_cve_updated ON cve(updated_at)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_software_name ON software(name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_matches_cve ON vulnerability_matches(cve_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_matches_status ON vulnerability_matches(status)')

            conn.commit()
            conn.close()

    def upsert_cve(self, cve: CVE) -> bool:
        """Вставка или обновление CVE"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute('''
                    INSERT OR REPLACE INTO cve 
                    (cve_id, description, published_date, last_modified_date,
                     cvss_v3_score, cvss_v3_vector, cvss_v3_severity, cvss_v2_score,
                     cwe_ids, "references", affected_products, exploit_available,
                     patch_available, raw_data, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve.cve_id,
                    cve.description,
                    cve.published_date,
                    cve.last_modified_date,
                    cve.cvss_v3_score,
                    cve.cvss_v3_vector,
                    cve.cvss_v3_severity,
                    cve.cvss_v2_score,
                    json.dumps(cve.cwe_ids),
                    json.dumps(cve.references),
                    json.dumps(cve.affected_products),
                    1 if cve.exploit_available else 0,
                    1 if cve.patch_available else 0,
                    json.dumps({'exploit_links': cve.exploit_links, 'patch_links': cve.patch_links}),
                    time.time()
                ))
                conn.commit()
                return True
            except Exception as e:
                print(f"Error upserting CVE {cve.cve_id}: {e}")
                return False
            finally:
                conn.close()

    def get_cve(self, cve_id: str) -> Optional[CVE]:
        """Получить CVE по ID"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute('SELECT * FROM cve WHERE cve_id = ?', (cve_id,)).fetchone()
                if row:
                    return self._row_to_cve(row)
                return None
            finally:
                conn.close()

    def search_cves(self, query: str = None, min_cvss: float = 0,
                    limit: int = 100) -> List[CVE]:
        """Поиск CVE"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                sql = 'SELECT * FROM cve WHERE cvss_v3_score >= ?'
                params = [min_cvss]

                if query:
                    sql += ' AND (cve_id LIKE ? OR description LIKE ?)'
                    params.extend([f'%{query}%', f'%{query}%'])

                sql += ' ORDER BY cvss_v3_score DESC LIMIT ?'
                params.append(limit)

                rows = conn.execute(sql, params).fetchall()
                return [self._row_to_cve(row) for row in rows]
            finally:
                conn.close()

    def _row_to_cve(self, row) -> CVE:
        """Конвертация строки в CVE"""
        raw_data = json.loads(row['raw_data'] or '{}')
        return CVE(
            cve_id=row['cve_id'],
            description=row['description'],
            published_date=row['published_date'],
            last_modified_date=row['last_modified_date'],
            cvss_v3_score=row['cvss_v3_score'],
            cvss_v3_vector=row['cvss_v3_vector'],
            cvss_v3_severity=row['cvss_v3_severity'],
            cvss_v2_score=row['cvss_v2_score'],
            cwe_ids=json.loads(row['cwe_ids'] or '[]'),
            references=json.loads(row['references'] or '[]'),
            affected_products=json.loads(row['affected_products'] or '[]'),
            exploit_available=bool(row['exploit_available']),
            exploit_links=raw_data.get('exploit_links', []),
            patch_available=bool(row['patch_available']),
            patch_links=raw_data.get('patch_links', [])
        )

    def add_software(self, software: Software) -> int:
        """Добавление ПО"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute('''
                    INSERT OR REPLACE INTO software 
                    (name, version, vendor, product, cpe, path, source, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    software.name,
                    software.version,
                    software.vendor,
                    software.product,
                    software.cpe,
                    software.path,
                    software.source,
                    software.last_seen
                ))
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def get_all_software(self) -> List[Software]:
        """Получить всё ПО"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute('SELECT * FROM software ORDER BY name').fetchall()
                return [Software(
                    name=row['name'],
                    version=row['version'],
                    vendor=row['vendor'],
                    product=row['product'],
                    cpe=row['cpe'],
                    path=row['path'],
                    source=row['source'],
                    last_seen=row['last_seen']
                ) for row in rows]
            finally:
                conn.close()

    def add_match(self, match: VulnerabilityMatch) -> bool:
        """Добавление совпадения"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    'SELECT id FROM software WHERE name = ? AND version = ?',
                    (match.software.name, match.software.version)
                )
                row = cursor.fetchone()
                if not row:
                    return False

                software_id = row[0]

                conn.execute('''
                    INSERT OR REPLACE INTO vulnerability_matches
                    (software_id, cve_id, status, confidence, risk_score, matched_by, remediation, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    software_id,
                    match.cve.cve_id,
                    match.status.value,
                    match.confidence,
                    match.risk_score,
                    match.matched_by,
                    match.remediation,
                    time.time()
                ))
                conn.commit()
                return True
            finally:
                conn.close()

    def get_vulnerable_software(self, min_risk: float = 7.0) -> List[Dict]:
        """Получить уязвимое ПО"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute('''
                    SELECT s.name, s.version, s.path, s.source,
                           c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
                           c.exploit_available, c.patch_available,
                           m.risk_score, m.status, m.remediation
                    FROM vulnerability_matches m
                    JOIN software s ON m.software_id = s.id
                    JOIN cve c ON m.cve_id = c.cve_id
                    WHERE m.risk_score >= ? AND m.status = 'VULNERABLE'
                    ORDER BY m.risk_score DESC
                ''', (min_risk,)).fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def get_stats(self) -> Dict:
        """Статистика базы данных"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                total_cves = conn.execute('SELECT COUNT(*) FROM cve').fetchone()[0]
                total_software = conn.execute('SELECT COUNT(*) FROM software').fetchone()[0]
                vulnerable = conn.execute(
                    'SELECT COUNT(*) FROM vulnerability_matches WHERE status = ?',
                    (CVEStatus.VULNERABLE.value,)
                ).fetchone()[0]

                severity_counts = {}
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = conn.execute(
                        'SELECT COUNT(*) FROM cve WHERE cvss_v3_severity = ?',
                        (severity,)
                    ).fetchone()[0]
                    severity_counts[severity] = count

                return {
                    'total_cves': total_cves,
                    'total_software': total_software,
                    'vulnerable_software': vulnerable,
                    'severity_distribution': severity_counts
                }
            finally:
                conn.close()



class NVDClient:
    """Клиент для National Vulnerability Database API"""

    def __init__(self, config: CVEIntelligenceConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SHARD-CVE-Intelligence/5.0.0'
        })
        if config.nvd_api_key:
            self.session.headers.update({'apiKey': config.nvd_api_key})

        self.rate_limit_delay = 6.0 if not config.nvd_api_key else 0.6
        self.last_request_time = 0

    def _rate_limit(self):
        """Соблюдение rate limit"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def fetch_cve(self, cve_id: str) -> Optional[CVE]:
        """Получение информации о конкретном CVE"""
        self._rate_limit()

        try:
            response = self.session.get(
                self.config.nvd_api_url,
                params={'cveId': cve_id},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                if vulnerabilities:
                    return self._parse_cve(vulnerabilities[0]['cve'])
            elif response.status_code == 404:
                return None
            else:
                print(f"NVD API error: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
            return None

    def fetch_recent_cves(self, start_index: int = 0, results_per_page: int = 100) -> List[CVE]:
        """Получение недавних CVE"""
        self._rate_limit()

        cves = []
        try:
            response = self.session.get(
                self.config.nvd_api_url,
                params={
                    'startIndex': start_index,
                    'resultsPerPage': min(results_per_page, 100)
                },
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = self._parse_cve(vuln['cve'])
                    if cve:
                        cves.append(cve)

        except Exception as e:
            print(f"Error fetching recent CVEs: {e}")

        return cves

    def fetch_modified_cves(self, hours: int = 24) -> List[CVE]:
        """Получение изменённых CVE за последние N часов"""
        self._rate_limit()

        cves = []
        pub_end_date = datetime.now().isoformat() + 'Z'
        pub_start_date = (datetime.now() - timedelta(hours=hours)).isoformat() + 'Z'

        try:
            response = self.session.get(
                self.config.nvd_api_url,
                params={
                    'lastModStartDate': pub_start_date,
                    'lastModEndDate': pub_end_date,
                    'resultsPerPage': 100
                },
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = self._parse_cve(vuln['cve'])
                    if cve:
                        cves.append(cve)

        except Exception as e:
            print(f"Error fetching modified CVEs: {e}")

        return cves

    def _parse_cve(self, data: Dict) -> Optional[CVE]:
        """Парсинг CVE из JSON"""
        try:
            cve_id = data['id']
            descriptions = data.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

            published = data.get('published', '')
            modified = data.get('lastModified', '')

            metrics = data.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0]
            cvss_v3_score = None
            cvss_v3_vector = None
            cvss_v3_severity = 'NONE'

            if cvss_v3:
                cvss_data = cvss_v3.get('cvssData', {})
                cvss_v3_score = cvss_data.get('baseScore')
                cvss_v3_vector = cvss_data.get('vectorString')
                cvss_v3_severity = cvss_data.get('baseSeverity', 'NONE')

            cvss_v2 = metrics.get('cvssMetricV2', [{}])[0]
            cvss_v2_score = None
            if cvss_v2:
                cvss_data = cvss_v2.get('cvssData', {})
                cvss_v2_score = cvss_data.get('baseScore')

            weaknesses = data.get('weaknesses', [])
            cwe_ids = []
            for w in weaknesses:
                for desc in w.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value', ''))

            references = [ref.get('url', '') for ref in data.get('references', [])]

            affected = []
            configurations = data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe = cpe_match.get('criteria', '')
                        if cpe:
                            affected.append(cpe)

            return CVE(
                cve_id=cve_id,
                description=description,
                published_date=published,
                last_modified_date=modified,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v3_severity=cvss_v3_severity,
                cvss_v2_score=cvss_v2_score,
                cwe_ids=cwe_ids,
                references=references,
                affected_products=affected
            )

        except Exception as e:
            print(f"Error parsing CVE: {e}")
            return None



class ExploitDBClient:
    """Клиент для проверки наличия эксплоитов"""

    def __init__(self, config: CVEIntelligenceConfig):
        self.config = config
        self.exploit_map: Dict[str, List[str]] = {}
        self._load_exploit_db()

    def _load_exploit_db(self):
        """Загрузка базы эксплоитов"""
        db_path = Path(self.config.exploit_db_path) / 'files_exploits.csv'
        if db_path.exists():
            try:
                import csv
                with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 3:
                            file_id = row[0]
                            description = row[2]
                            cve_pattern = r'CVE-\d{4}-\d{4,}'
                            cves = re.findall(cve_pattern, description, re.IGNORECASE)
                            for cve in cves:
                                if cve not in self.exploit_map:
                                    self.exploit_map[cve] = []
                                self.exploit_map[cve].append(f"https://www.exploit-db.com/exploits/{file_id}")
            except Exception as e:
                print(f"Error loading ExploitDB: {e}")

    def check_exploit(self, cve_id: str) -> Tuple[bool, List[str]]:
        """Проверка наличия эксплоита"""
        links = self.exploit_map.get(cve_id, [])
        return len(links) > 0, links

    def download_exploit_db(self):
        """Скачивание свежей базы ExploitDB"""
        import zipfile
        import io

        db_dir = Path(self.config.exploit_db_path)
        db_dir.mkdir(parents=True, exist_ok=True)

        try:
            response = requests.get(
                'https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv',
                timeout=60
            )
            if response.status_code == 200:
                with open(db_dir / 'files_exploits.csv', 'w', encoding='utf-8') as f:
                    f.write(response.text)
                self._load_exploit_db()
                return True
        except Exception as e:
            print(f"Error downloading ExploitDB: {e}")

        return False



class SoftwareScanner:
    """Сканер установленного программного обеспечения"""

    def __init__(self):
        self.scanners = {
            'linux': self._scan_linux,
            'windows': self._scan_windows,
            'python': self._scan_python_packages,
            'node': self._scan_node_packages,
            'go': self._scan_go_modules,
            'docker': self._scan_docker_images
        }

    def scan_system(self) -> List[Software]:
        """Сканирование системы"""
        software = []

        if os.name == 'nt':
            software.extend(self._scan_windows())
        else:
            software.extend(self._scan_linux())

        return software

    def scan_dependencies(self, project_path: str) -> List[Software]:
        """Сканирование зависимостей проекта"""
        software = []
        path = Path(project_path)

        if (path / 'requirements.txt').exists() or (path / 'Pipfile').exists():
            software.extend(self._scan_python_packages(path))

        if (path / 'package.json').exists():
            software.extend(self._scan_node_packages(path))

        if (path / 'go.mod').exists():
            software.extend(self._scan_go_modules(path))

        if (path / 'Dockerfile').exists() or (path / 'docker-compose.yml').exists():
            software.extend(self._scan_docker_images(path))

        return software

    def _scan_linux(self) -> List[Software]:
        """Сканирование Linux (dpkg/rpm)"""
        software = []

        try:
            import subprocess
            result = subprocess.run(['dpkg-query', '-W', '-f=${Package}\t${Version}\n'],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            software.append(Software(
                                name=parts[0],
                                version=parts[1],
                                source='dpkg',
                                last_seen=time.time()
                            ))
        except:
            pass

        try:
            import subprocess
            result = subprocess.run(['rpm', '-qa', '--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\n'],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            software.append(Software(
                                name=parts[0],
                                version=parts[1],
                                source='rpm',
                                last_seen=time.time()
                            ))
        except:
            pass

        return software

    def _scan_windows(self) -> List[Software]:
        """Сканирование Windows (реестр)"""
        software = []

        try:
            import winreg

            for hive, path in [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            ]:
                try:
                    key = winreg.OpenKey(hive, path)
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)

                            name = None
                            version = None
                            try:
                                name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                version = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
                            except:
                                pass

                            if name:
                                software.append(Software(
                                    name=name,
                                    version=version or 'unknown',
                                    source='windows_registry',
                                    last_seen=time.time()
                                ))

                            winreg.CloseKey(subkey)
                        except:
                            pass
                    winreg.CloseKey(key)
                except:
                    pass
        except:
            pass

        return software

    def _scan_python_packages(self, project_path: Path) -> List[Software]:
        """Сканирование Python пакетов"""
        software = []

        try:
            import subprocess
            result = subprocess.run(['pip', 'freeze'], capture_output=True, text=True, timeout=30, cwd=project_path)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '==' in line:
                        name, version = line.split('==', 1)
                        software.append(Software(
                            name=name.strip(),
                            version=version.strip(),
                            source='pip',
                            last_seen=time.time()
                        ))
        except:
            pass

        return software

    def _scan_node_packages(self, project_path: Path) -> List[Software]:
        """Сканирование Node.js пакетов"""
        software = []
        package_json = project_path / 'package.json'

        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)
                    for dep_type in ['dependencies', 'devDependencies']:
                        for name, version in data.get(dep_type, {}).items():
                            clean_version = version.replace('^', '').replace('~', '').replace('>', '').replace('<',
                                                                                                               '').replace(
                                '=', '')
                            software.append(Software(
                                name=name,
                                version=clean_version,
                                source='npm',
                                last_seen=time.time()
                            ))
            except:
                pass

        return software

    def _scan_go_modules(self, project_path: Path) -> List[Software]:
        """Сканирование Go модулей"""
        software = []
        go_mod = project_path / 'go.mod'

        if go_mod.exists():
            try:
                with open(go_mod, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('module') and not line.startswith('go '):
                            parts = line.split()
                            if len(parts) >= 2:
                                software.append(Software(
                                    name=parts[0],
                                    version=parts[1],
                                    source='go',
                                    last_seen=time.time()
                                ))
            except:
                pass

        return software

    def _scan_docker_images(self, project_path: Path) -> List[Software]:
        """Сканирование Docker образов"""
        software = []

        try:
            import subprocess
            result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}\t{{.Tag}}'],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            software.append(Software(
                                name=parts[0],
                                version=parts[1],
                                source='docker',
                                last_seen=time.time()
                            ))
        except:
            pass

        return software



class CVEMatcher:
    """Сопоставление CVE с установленным ПО"""

    def __init__(self, database: CVEDatabase):
        self.database = database
        self.cpe_to_cve: Dict[str, List[str]] = defaultdict(list)
        self._build_index()

    def _build_index(self):
        """Построение индекса CPE -> CVE"""
        cves = self.database.search_cves(min_cvss=0, limit=100000)

        for cve in cves:
            for cpe in cve.affected_products:
                self.cpe_to_cve[cpe].append(cve.cve_id)

    def match_software(self, software: Software) -> List[VulnerabilityMatch]:
        """Поиск CVE для ПО"""
        matches = []

        cpes = self._generate_cpes(software)

        seen_cves = set()
        for cpe in cpes:
            cve_ids = self.cpe_to_cve.get(cpe, [])
            for cve_id in cve_ids:
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                cve = self.database.get_cve(cve_id)
                if cve:
                    risk_score = self._calculate_risk_score(software, cve)
                    match = VulnerabilityMatch(
                        software=software,
                        cve=cve,
                        status=CVEStatus.VULNERABLE,
                        confidence=0.9,
                        risk_score=risk_score,
                        matched_by='cpe',
                        remediation=self._get_remediation(cve)
                    )
                    matches.append(match)

        if not matches:
            cves = self.database.search_cves(query=software.name, min_cvss=0, limit=10)
            for cve in cves:
                if self._version_in_range(software.version, cve):
                    risk_score = self._calculate_risk_score(software, cve)
                    match = VulnerabilityMatch(
                        software=software,
                        cve=cve,
                        status=CVEStatus.VULNERABLE,
                        confidence=0.6,
                        risk_score=risk_score,
                        matched_by='name',
                        remediation=self._get_remediation(cve)
                    )
                    matches.append(match)

        return matches

    def _generate_cpes(self, software: Software) -> List[str]:
        """Генерация возможных CPE для ПО"""
        cpes = []
        name = software.name.lower()
        version = software.version

        vendors = [software.vendor, '*', 'apache', 'microsoft', 'google', 'oracle', 'redhat']
        for vendor in vendors:
            if vendor:
                cpes.append(f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*")
                cpes.append(f"cpe:2.3:a:*:{name}:{version}:*:*:*:*:*:*:*")

        return cpes

    def _version_in_range(self, version: str, cve: CVE) -> bool:
        """Проверка версии в диапазоне"""
        for product in cve.affected_products:
            if version in product:
                return True
        return False

    def _calculate_risk_score(self, software: Software, cve: CVE) -> float:
        """Расчёт риска для конкретного ПО"""
        base_score = cve.cvss_v3_score or cve.cvss_v2_score or 5.0
        risk = base_score / 10.0

        if cve.exploit_available:
            risk = min(1.0, risk * 1.3)

        critical_software = ['openssl', 'nginx', 'apache', 'mysql', 'postgresql', 'redis', 'docker']
        if any(cs in software.name.lower() for cs in critical_software):
            risk = min(1.0, risk * 1.2)

        return risk

    def _get_remediation(self, cve: CVE) -> Optional[str]:
        """Получение рекомендаций по исправлению"""
        if cve.patch_available:
            return f"Update to patched version. References: {', '.join(cve.references[:3])}"

        severity = cve.get_severity()
        if severity in [CVESeverity.CRITICAL, CVESeverity.HIGH]:
            return "Immediate patching required. Check vendor advisory."
        elif severity == CVESeverity.MEDIUM:
            return "Plan to patch in next maintenance window."
        else:
            return "Monitor for updates."



class CVEIntelligenceEngine:
    """
    Движок CVE Intelligence
    Объединяет все компоненты для анализа уязвимостей
    """

    def __init__(self, config: CVEIntelligenceConfig = None):
        self.config = config or CVEIntelligenceConfig()
        self.database = CVEDatabase(self.config.cve_database_path)
        self.nvd_client = NVDClient(self.config)
        self.exploit_client = ExploitDBClient(self.config)
        self.software_scanner = SoftwareScanner()
        self.matcher = CVEMatcher(self.database)

        self.stats = {
            'total_cves_fetched': 0,
            'total_software_scanned': 0,
            'total_matches': 0,
            'critical_vulnerabilities': 0
        }

        self._lock = threading.RLock()
        self._running = False
        self._update_thread = None

    def start(self):
        """Запуск движка"""
        self._running = True

        if self.config.auto_update:
            self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
            self._update_thread.start()

        print("🚀 CVE Intelligence Engine запущен")

    def stop(self):
        """Остановка движка"""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)
        print("🛑 CVE Intelligence Engine остановлен")

    def _update_loop(self):
        """Цикл обновления CVE"""
        while self._running:
            self.update_cve_database()
            time.sleep(self.config.update_interval_hours * 3600)

    def update_cve_database(self, max_cves: int = None) -> int:
        """Обновление базы CVE"""
        max_cves = max_cves or self.config.max_cves_per_update
        fetched = 0

        print("🔄 Обновление базы CVE...")

        start_index = 0
        while fetched < max_cves:
            cves = self.nvd_client.fetch_recent_cves(start_index, 100)
            if not cves:
                break

            for cve in cves:
                has_exploit, exploit_links = self.exploit_client.check_exploit(cve.cve_id)
                cve.exploit_available = has_exploit
                cve.exploit_links = exploit_links

                if self.database.upsert_cve(cve):
                    fetched += 1
                    with self._lock:
                        self.stats['total_cves_fetched'] += 1

            start_index += 100

            time.sleep(1)

        print(f"✅ Обновлено {fetched} CVE")
        return fetched

    def scan_infrastructure(self) -> List[VulnerabilityMatch]:
        """Сканирование инфраструктуры на уязвимости"""
        matches = []

        print("🔍 Сканирование инфраструктуры...")

        system_software = self.software_scanner.scan_system()
        with self._lock:
            self.stats['total_software_scanned'] += len(system_software)

        for sw in system_software:
            self.database.add_software(sw)
            sw_matches = self.matcher.match_software(sw)
            for match in sw_matches:
                self.database.add_match(match)
                matches.append(match)

                with self._lock:
                    self.stats['total_matches'] += 1
                    if match.risk_score >= 0.9:
                        self.stats['critical_vulnerabilities'] += 1

        print(f"✅ Найдено {len(matches)} уязвимостей")
        return matches

    def scan_project(self, project_path: str) -> List[VulnerabilityMatch]:
        """Сканирование проекта (зависимостей)"""
        matches = []

        print(f"🔍 Сканирование проекта: {project_path}")

        deps = self.software_scanner.scan_dependencies(project_path)
        with self._lock:
            self.stats['total_software_scanned'] += len(deps)

        for dep in deps:
            self.database.add_software(dep)
            dep_matches = self.matcher.match_software(dep)
            for match in dep_matches:
                self.database.add_match(match)
                matches.append(match)

                with self._lock:
                    self.stats['total_matches'] += 1
                    if match.risk_score >= 0.9:
                        self.stats['critical_vulnerabilities'] += 1

        print(f"✅ Найдено {len(matches)} уязвимостей в зависимостях")
        return matches

    def check_cve(self, cve_id: str) -> Optional[CVE]:
        """Проверка конкретного CVE"""
        cve = self.database.get_cve(cve_id)
        if cve and time.time() - float(cve.last_modified_date) < self.config.cache_ttl:
            return cve

        cve = self.nvd_client.fetch_cve(cve_id)
        if cve:
            has_exploit, exploit_links = self.exploit_client.check_exploit(cve_id)
            cve.exploit_available = has_exploit
            cve.exploit_links = exploit_links
            self.database.upsert_cve(cve)

        return cve

    def get_vulnerability_report(self) -> Dict:
        """Получить отчёт об уязвимостях"""
        vulnerable = self.database.get_vulnerable_software(min_risk=0)

        critical = [v for v in vulnerable if v.get('risk_score', 0) >= 0.9]
        high = [v for v in vulnerable if 0.7 <= v.get('risk_score', 0) < 0.9]
        medium = [v for v in vulnerable if 0.4 <= v.get('risk_score', 0) < 0.7]
        low = [v for v in vulnerable if v.get('risk_score', 0) < 0.4]

        return {
            'timestamp': time.time(),
            'summary': {
                'total_vulnerabilities': len(vulnerable),
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium),
                'low': len(low)
            },
            'vulnerabilities': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low
            },
            'stats': self.database.get_stats()
        }

    def generate_report(self, format: str = 'json') -> str:
        """Генерация отчёта"""
        report_data = self.get_vulnerability_report()

        if format == 'json':
            return json.dumps(report_data, indent=2)
        elif format == 'html':
            return self._to_html(report_data)
        else:
            return self._to_text(report_data)

    def _to_html(self, report_data: Dict) -> str:
        """HTML отчёт"""
        summary = report_data['summary']

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SHARD CVE Intelligence Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color:
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ padding: 20px; border-radius: 10px; color: white; min-width: 100px; text-align: center; }}
        .critical {{ background:
        .high {{ background:
        .medium {{ background:
        .low {{ background:
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid
        th {{ background:
        .exploit {{ color:
    </style>
</head>
<body>
    <h1>🛡️ SHARD CVE Intelligence Report</h1>
    <p>Generated: {datetime.fromtimestamp(report_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="summary">
        <div class="card critical">
            <h2>{summary['critical']}</h2>
            <div>CRITICAL</div>
        </div>
        <div class="card high">
            <h2>{summary['high']}</h2>
            <div>HIGH</div>
        </div>
        <div class="card medium">
            <h2>{summary['medium']}</h2>
            <div>MEDIUM</div>
        </div>
        <div class="card low">
            <h2>{summary['low']}</h2>
            <div>LOW</div>
        </div>
    </div>

    <h2>Critical Vulnerabilities</h2>
    <table>
        <tr>
            <th>Software</th>
            <th>Version</th>
            <th>CVE</th>
            <th>CVSS</th>
            <th>Risk</th>
            <th>Exploit</th>
            <th>Remediation</th>
        </tr>
"""

        for vuln in report_data['vulnerabilities']['critical']:
            exploit_icon = '⚠️' if vuln.get('exploit_available') else ''
            html += f"""
        <tr>
            <td>{vuln.get('name', 'N/A')}</td>
            <td>{vuln.get('version', 'N/A')}</td>
            <td>{vuln.get('cve_id', 'N/A')}</td>
            <td>{vuln.get('cvss_v3_score', 'N/A')}</td>
            <td>{vuln.get('risk_score', 0):.0%}</td>
            <td class="exploit">{exploit_icon}</td>
            <td>{vuln.get('remediation', 'N/A')[:100]}</td>
        </tr>
"""

        html += """
    </table>
</body>
</html>
"""
        return html

    def _to_text(self, report_data: Dict) -> str:
        """Текстовый отчёт"""
        lines = []
        lines.append("=" * 80)
        lines.append("SHARD CVE INTELLIGENCE REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.fromtimestamp(report_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append(f"Total Vulnerabilities: {report_data['summary']['total_vulnerabilities']}")
        lines.append(f"  CRITICAL: {report_data['summary']['critical']}")
        lines.append(f"  HIGH: {report_data['summary']['high']}")
        lines.append(f"  MEDIUM: {report_data['summary']['medium']}")
        lines.append(f"  LOW: {report_data['summary']['low']}")
        lines.append("")

        if report_data['vulnerabilities']['critical']:
            lines.append("CRITICAL VULNERABILITIES:")
            for vuln in report_data['vulnerabilities']['critical']:
                lines.append(
                    f"  - {vuln.get('name')} {vuln.get('version')}: {vuln.get('cve_id')} (CVSS: {vuln.get('cvss_v3_score')})")
                lines.append(f"    Remediation: {vuln.get('remediation', 'N/A')}")

        lines.append("")
        lines.append("=" * 80)
        return '\n'.join(lines)

    def save_report(self, filename: str = None) -> str:
        """Сохранение отчёта"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cve_report_{timestamp}.json"

        report_path = Path(self.config.reports_dir) / filename
        report_path.parent.mkdir(parents=True, exist_ok=True)

        report = self.generate_report('json')
        with open(report_path, 'w') as f:
            f.write(report)

        return str(report_path)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return {
                **self.stats,
                'database_stats': self.database.get_stats()
            }



class ShardCVEIntelligenceIntegration:
    """Интеграция CVE Intelligence в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = CVEIntelligenceConfig()
        self.engine = CVEIntelligenceEngine(self.config)
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger):
        """Настройка интеграции"""
        self.event_bus = event_bus
        self.logger = logger

        if event_bus:
            event_bus.subscribe('cve.check', self.on_check_cve)
            event_bus.subscribe('cve.scan', self.on_scan_infrastructure)

    def start(self):
        """Запуск интеграции"""
        self.engine.start()

        if self.config.scan_installed_software:
            threading.Thread(target=self._initial_scan, daemon=True).start()

        if self.logger:
            self.logger.info("🚀 CVE Intelligence запущен")

    def stop(self):
        """Остановка интеграции"""
        self.engine.stop()

    def _initial_scan(self):
        """Первоначальное сканирование"""
        time.sleep(5)
        matches = self.engine.scan_infrastructure()

        for match in matches:
            if match.risk_score >= 0.7:
                self._publish_alert(match)

    def _publish_alert(self, match: VulnerabilityMatch):
        """Публикация уязвимости как алерта"""
        if self.event_bus:
            severity = 'CRITICAL' if match.risk_score >= 0.9 else 'HIGH'
            self.event_bus.publish('alert.detected', {
                'attack_type': 'Known Vulnerability',
                'severity': severity,
                'score': match.risk_score,
                'confidence': match.confidence,
                'explanation': f"CVE-{match.cve.cve_id}: {match.cve.description[:200]}",
                'details': {
                    'cve_id': match.cve.cve_id,
                    'software': f"{match.software.name} {match.software.version}",
                    'cvss_score': match.cve.cvss_v3_score,
                    'exploit_available': match.cve.exploit_available,
                    'remediation': match.remediation
                }
            })

            if self.logger:
                self.logger.warning(
                    f"🔴 Уязвимость: {match.software.name} → {match.cve.cve_id} (Risk: {match.risk_score:.0%})")

    def on_check_cve(self, data: Dict):
        """Обработка запроса проверки CVE"""
        cve_id = data.get('cve_id', '')
        cve = self.engine.check_cve(cve_id)

        if self.event_bus:
            self.event_bus.publish('cve.result', {
                'cve_id': cve_id,
                'cve': {
                    'description': cve.description if cve else None,
                    'cvss_score': cve.cvss_v3_score if cve else None,
                    'severity': cve.cvss_v3_severity if cve else None,
                    'exploit_available': cve.exploit_available if cve else False
                },
                'request_id': data.get('request_id')
            })

    def on_scan_infrastructure(self, data: Dict):
        """Обработка запроса сканирования"""
        matches = self.engine.scan_infrastructure()

        for match in matches:
            if match.risk_score >= 0.7:
                self._publish_alert(match)

        if self.event_bus:
            self.event_bus.publish('cve.scan.completed', {
                'total_matches': len(matches),
                'critical': sum(1 for m in matches if m.risk_score >= 0.9),
                'high': sum(1 for m in matches if 0.7 <= m.risk_score < 0.9),
                'request_id': data.get('request_id')
            })

    def scan_project(self, project_path: str) -> List[VulnerabilityMatch]:
        """Сканирование проекта"""
        return self.engine.scan_project(project_path)

    def get_report(self) -> Dict:
        """Получить отчёт"""
        return self.engine.get_vulnerability_report()

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return self.engine.get_stats()



def test_cve_intelligence():
    """Тестирование CVE Intelligence"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ CVE INTELLIGENCE")
    print("=" * 60)

    config = CVEIntelligenceConfig()
    config.auto_update = False
    config.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    engine = CVEIntelligenceEngine(config)

    print("\n📝 Тест 1: Проверка CVE-2021-44228 (Log4Shell)")
    cve = engine.check_cve("CVE-2021-44228")
    if cve:
        print(f"   CVE ID: {cve.cve_id}")
        print(f"   Description: {cve.description[:100]}...")
        print(f"   CVSS v3: {cve.cvss_v3_score}")
        print(f"   Severity: {cve.cvss_v3_severity}")
        print(f"   Exploit available: {cve.exploit_available}")

    print("\n📝 Тест 2: Сканирование установленного ПО")
    software = engine.software_scanner.scan_system()
    print(f"   Найдено ПО: {len(software)}")
    for sw in software[:5]:
        print(f"      - {sw.name} {sw.version} (source: {sw.source})")

    print("\n📝 Тест 3: Генерация отчёта")
    report = engine.generate_report('json')
    print(f"   Отчёт сгенерирован, размер: {len(report)} байт")

    print("\n📊 Статистика:")
    stats = engine.get_stats()
    for key, value in stats.items():
        if not isinstance(value, dict):
            print(f"   {key}: {value}")

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_cve_intelligence()
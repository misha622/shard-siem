#!/usr/bin/env python3

"""
SHARD MITRE ATT&CK Full Coverage Module
Полное покрытие MITRE ATT&CK — автоматическое сопоставление, навигатор, оценка покрытия

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
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

import requests
import yaml



@dataclass
class MITREConfig:
    """Конфигурация MITRE ATT&CK"""

    enterprise_attack_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    mobile_attack_url: str = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
    ics_attack_url: str = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"

    data_dir: str = "./data/mitre/"
    db_path: str = "./data/mitre/mitre.db"

    auto_update: bool = True
    update_interval_days: int = 7

    custom_mappings_path: str = "./data/mitre/custom_mappings.yaml"

    reports_dir: str = "./data/mitre/reports/"


@dataclass
class MITRETactic:
    """Тактика MITRE ATT&CK"""
    id: str
    name: str
    description: str
    short_name: str
    phases: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)


@dataclass
class MITRETechnique:
    """Техника MITRE ATT&CK"""
    id: str
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection_recommendations: str = ""
    mitigations: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)
    parent_technique: Optional[str] = None
    is_sub_technique: bool = False


@dataclass
class MITREGroup:
    """Группировка MITRE ATT&CK"""
    id: str
    name: str
    description: str
    aliases: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)


@dataclass
class MITRESoftware:
    """ПО MITRE ATT&CK"""
    id: str
    name: str
    description: str
    type: str
    platforms: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)


@dataclass
class MITREMitigation:
    """Меры защиты MITRE ATT&CK"""
    id: str
    name: str
    description: str
    techniques: List[str] = field(default_factory=list)



class MITRELoader:
    """Загрузчик данных MITRE ATT&CK"""

    def __init__(self, config: MITREConfig, logger=None):
        self.config = config
        self.logger = logger

        self.tactics: Dict[str, MITRETactic] = {}
        self.techniques: Dict[str, MITRETechnique] = {}
        self.sub_techniques: Dict[str, MITRETechnique] = {}
        self.groups: Dict[str, MITREGroup] = {}
        self.software: Dict[str, MITRESoftware] = {}
        self.mitigations: Dict[str, MITREMitigation] = {}

        self.techniques_by_tactic: Dict[str, List[str]] = defaultdict(list)
        self.techniques_by_platform: Dict[str, List[str]] = defaultdict(list)
        self.groups_by_technique: Dict[str, List[str]] = defaultdict(list)
        self.software_by_technique: Dict[str, List[str]] = defaultdict(list)
        self.mitigations_by_technique: Dict[str, List[str]] = defaultdict(list)

        self._lock = threading.RLock()
        self._loaded = False

    def load(self, force_reload: bool = False) -> bool:
        """Загрузка данных MITRE ATT&CK"""
        if self._loaded and not force_reload:
            return True

        try:
            data_path = Path(self.config.data_dir) / "enterprise-attack.json"

            if not data_path.exists():
                self._download_attack_data()

            if data_path.exists():
                with open(data_path, 'r') as f:
                    data = json.load(f)
                    self._parse_attack_data(data)

                self._loaded = True

                if self.logger:
                    self.logger.info(
                        f"✅ MITRE ATT&CK loaded: {len(self.tactics)} tactics, {len(self.techniques)} techniques, {len(self.sub_techniques)} sub-techniques")

                return True
            else:
                self._load_embedded_data()
                self._loaded = True
                return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error loading MITRE ATT&CK: {e}")
            self._load_embedded_data()
            self._loaded = True
            return False

    def _download_attack_data(self):
        """Скачивание данных MITRE ATT&CK"""
        data_dir = Path(self.config.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)

        try:
            response = requests.get(self.config.enterprise_attack_url, timeout=60)
            if response.status_code == 200:
                with open(data_dir / "enterprise-attack.json", 'w') as f:
                    f.write(response.text)
                if self.logger:
                    self.logger.info("✅ MITRE ATT&CK data downloaded")
            else:
                raise Exception(f"HTTP {response.status_code}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error downloading MITRE ATT&CK: {e}")
            raise

    def _parse_attack_data(self, data: Dict):
        """Парсинг данных MITRE ATT&CK"""
        with self._lock:
            objects = data.get('objects', [])

            for obj in objects:
                obj_type = obj.get('type')
                obj_id = obj.get('id')

                if obj_type == 'x-mitre-tactic':
                    tactic = MITRETactic(
                        id=obj_id,
                        name=obj.get('name', ''),
                        description=obj.get('description', ''),
                        short_name=obj.get('x_mitre_shortname', ''),
                        platforms=obj.get('x_mitre_platforms', [])
                    )
                    self.tactics[obj_id] = tactic

                elif obj_type == 'attack-pattern':
                    is_sub = obj.get('x_mitre_is_subtechnique', False)

                    external_id = None
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            external_id = ref.get('external_id')
                            break

                    if external_id:
                        technique = MITRETechnique(
                            id=external_id,
                            name=obj.get('name', ''),
                            description=obj.get('description', ''),
                            platforms=obj.get('x_mitre_platforms', []),
                            permissions_required=obj.get('x_mitre_permissions_required', []),
                            data_sources=obj.get('x_mitre_data_sources', []),
                            detection_recommendations=obj.get('x_mitre_detection', ''),
                            is_sub_technique=is_sub
                        )

                        for phase in obj.get('kill_chain_phases', []):
                            if phase.get('kill_chain_name') == 'mitre-attack':
                                tactic_name = phase.get('phase_name', '')
                                technique.tactics.append(tactic_name)
                                self.techniques_by_tactic[tactic_name].append(external_id)

                        if is_sub:
                            self.sub_techniques[external_id] = technique
                        else:
                            self.techniques[external_id] = technique

                elif obj_type == 'intrusion-set':
                    group = MITREGroup(
                        id=obj_id,
                        name=obj.get('name', ''),
                        description=obj.get('description', ''),
                        aliases=obj.get('aliases', [])
                    )
                    self.groups[obj_id] = group

                elif obj_type in ['malware', 'tool']:
                    software = MITRESoftware(
                        id=obj_id,
                        name=obj.get('name', ''),
                        description=obj.get('description', ''),
                        type=obj_type,
                        platforms=obj.get('x_mitre_platforms', []),
                        aliases=obj.get('x_mitre_aliases', [])
                    )
                    self.software[obj_id] = software

                elif obj_type == 'course-of-action':
                    mitigation = MITREMitigation(
                        id=obj_id,
                        name=obj.get('name', ''),
                        description=obj.get('description', '')
                    )
                    self.mitigations[obj_id] = mitigation

            for obj in objects:
                if obj.get('type') == 'relationship':
                    source_ref = obj.get('source_ref')
                    target_ref = obj.get('target_ref')
                    rel_type = obj.get('relationship_type')

                    if source_ref in self.groups and target_ref in self.techniques:
                        tech_id = self.techniques[target_ref].id
                        if tech_id:
                            self.groups[source_ref].techniques.append(tech_id)
                            self.groups_by_technique[tech_id].append(source_ref)

                    elif source_ref in self.software and target_ref in self.techniques:
                        tech_id = self.techniques[target_ref].id
                        if tech_id:
                            self.software[source_ref].techniques.append(tech_id)
                            self.software_by_technique[tech_id].append(source_ref)

                    elif source_ref in self.mitigations and target_ref in self.techniques:
                        tech_id = self.techniques[target_ref].id
                        if tech_id:
                            self.mitigations[source_ref].techniques.append(tech_id)
                            self.mitigations_by_technique[tech_id].append(source_ref)

                    elif rel_type == 'subtechnique-of':
                        if source_ref in self.sub_techniques:
                            for tech in self.techniques.values():
                                if tech.id and target_ref in str(tech.id):
                                    parent_id = tech.id
                                    self.sub_techniques[source_ref].parent_technique = parent_id
                                    if parent_id in self.techniques:
                                        self.techniques[parent_id].sub_techniques.append(
                                            self.sub_techniques[source_ref].id
                                        )

    def _load_embedded_data(self):
        """Загрузка встроенного подмножества MITRE ATT&CK"""
        with self._lock:
            tactics_data = [
                ('TA0043', 'Reconnaissance', 'reconnaissance'),
                ('TA0042', 'Resource Development', 'resource-development'),
                ('TA0001', 'Initial Access', 'initial-access'),
                ('TA0002', 'Execution', 'execution'),
                ('TA0003', 'Persistence', 'persistence'),
                ('TA0004', 'Privilege Escalation', 'privilege-escalation'),
                ('TA0005', 'Defense Evasion', 'defense-evasion'),
                ('TA0006', 'Credential Access', 'credential-access'),
                ('TA0007', 'Discovery', 'discovery'),
                ('TA0008', 'Lateral Movement', 'lateral-movement'),
                ('TA0009', 'Collection', 'collection'),
                ('TA0011', 'Command and Control', 'command-and-control'),
                ('TA0010', 'Exfiltration', 'exfiltration'),
                ('TA0040', 'Impact', 'impact'),
            ]

            for tid, name, short in tactics_data:
                self.tactics[tid] = MITRETactic(
                    id=tid, name=name, description='', short_name=short
                )

            techniques_data = [
                ('T1059', 'Command and Scripting Interpreter', ['Execution']),
                ('T1059.001', 'PowerShell', ['Execution']),
                ('T1059.003', 'Windows Command Shell', ['Execution']),
                ('T1003', 'OS Credential Dumping', ['Credential Access']),
                ('T1003.001', 'LSASS Memory', ['Credential Access']),
                ('T1021', 'Remote Services', ['Lateral Movement']),
                ('T1021.002', 'SMB/Windows Admin Shares', ['Lateral Movement']),
                ('T1046', 'Network Service Scanning', ['Discovery']),
                ('T1048', 'Exfiltration Over Alternative Protocol', ['Exfiltration']),
                ('T1071', 'Application Layer Protocol', ['Command and Control']),
                ('T1082', 'System Information Discovery', ['Discovery']),
                ('T1090', 'Proxy', ['Command and Control']),
                ('T1110', 'Brute Force', ['Credential Access']),
                ('T1190', 'Exploit Public-Facing Application', ['Initial Access']),
                ('T1486', 'Data Encrypted for Impact', ['Impact']),
                ('T1498', 'Network Denial of Service', ['Impact']),
                ('T1547', 'Boot or Logon Autostart Execution', ['Persistence', 'Privilege Escalation']),
                ('T1566', 'Phishing', ['Initial Access']),
                ('T1572', 'Protocol Tunneling', ['Command and Control']),
            ]

            for tid, name, tactics in techniques_data:
                tech = MITRETechnique(
                    id=tid, name=name, description='',
                    tactics=tactics,
                    is_sub_technique=('.' in tid)
                )
                if '.' in tid:
                    self.sub_techniques[tid] = tech
                    parent = tid.split('.')[0]
                    if parent in self.techniques:
                        self.techniques[parent].sub_techniques.append(tid)
                else:
                    self.techniques[tid] = tech

                for t in tactics:
                    self.techniques_by_tactic[t].append(tid)



class MITREMapper:
    """Маппер алертов на MITRE ATT&CK"""

    def __init__(self, loader: MITRELoader, config: MITREConfig, logger=None):
        self.loader = loader
        self.config = config
        self.logger = logger
        self.custom_mappings: Dict[str, List[str]] = {}
        self._load_custom_mappings()

    def _load_custom_mappings(self):
        """Загрузка кастомных маппингов"""
        mapping_path = Path(self.config.custom_mappings_path)
        if mapping_path.exists():
            try:
                with open(mapping_path, 'r') as f:
                    self.custom_mappings = yaml.safe_load(f) or {}
            except:
                pass

    def map_alert(self, alert: Dict) -> Dict[str, Any]:
        """Маппинг алерта на MITRE ATT&CK"""
        attack_type = alert.get('attack_type', '')
        alert_data = alert.get('details', {})
        description = alert.get('explanation', '')

        techniques = self._find_techniques(attack_type, alert_data, description)

        tactics = set()
        for tech_id in techniques:
            tech = self.loader.techniques.get(tech_id) or self.loader.sub_techniques.get(tech_id)
            if tech:
                tactics.update(tech.tactics)

        groups = set()
        for tech_id in techniques:
            groups.update(self.loader.groups_by_technique.get(tech_id, []))

        software = set()
        for tech_id in techniques:
            software.update(self.loader.software_by_technique.get(tech_id, []))

        mitigations = set()
        for tech_id in techniques:
            mitigations.update(self.loader.mitigations_by_technique.get(tech_id, []))

        return {
            'tactics': list(tactics),
            'techniques': list(techniques),
            'groups': list(groups),
            'software': list(software),
            'mitigations': list(mitigations),
            'confidence': self._calculate_confidence(techniques)
        }

    def _find_techniques(self, attack_type: str, alert_data: Dict, description: str) -> Set[str]:
        """Поиск подходящих техник"""
        techniques = set()

        attack_mapping = {
            'Brute Force': ['T1110'],
            'Port Scan': ['T1046'],
            'Web Attack': ['T1190'],
            'SQL Injection': ['T1190'],
            'XSS': ['T1189', 'T1059.007'],
            'DDoS': ['T1498'],
            'Data Exfiltration': ['T1048', 'T1041'],
            'Lateral Movement': ['T1021'],
            'Phishing': ['T1566'],
            'Malware': ['T1204'],
            'C2 Beacon': ['T1071'],
            'DNS Tunnel': ['T1572'],
            'PowerShell': ['T1059.001'],
            'Credential Dumping': ['T1003'],
            'Registry Persistence': ['T1547.001'],
            'Scheduled Task': ['T1053'],
            'WMI': ['T1047'],
        }

        if attack_type in attack_mapping:
            techniques.update(attack_mapping[attack_type])

        keyword_mapping = {
            'powershell': ['T1059.001'],
            'cmd.exe': ['T1059.003'],
            'wmic': ['T1047'],
            'schtasks': ['T1053'],
            'reg.exe': ['T1112'],
            'net.exe': ['T1087'],
            'mimikatz': ['T1003.001'],
            'lsass': ['T1003.001'],
            'psexec': ['T1021.002'],
            'ssh': ['T1021.004'],
            'rdp': ['T1021.001'],
            'smb': ['T1021.002'],
            'dns': ['T1071.004'],
            'http': ['T1071.001'],
            'https': ['T1071.001'],
            'base64': ['T1027'],
            'obfuscated': ['T1027'],
            'encoded': ['T1027'],
            'phishing': ['T1566'],
            'spearphishing': ['T1566.001'],
            'macro': ['T1059.005'],
            'vba': ['T1059.005'],
            'javascript': ['T1059.007'],
            'vbs': ['T1059.005'],
        }

        desc_lower = description.lower()
        for keyword, techs in keyword_mapping.items():
            if keyword in desc_lower:
                techniques.update(techs)

        for pattern, techs in self.custom_mappings.items():
            if re.search(pattern, description, re.IGNORECASE):
                techniques.update(techs)

        if alert_data:
            if alert_data.get('port') in [445, 139]:
                techniques.add('T1021.002')
            if alert_data.get('port') == 3389:
                techniques.add('T1021.001')
            if alert_data.get('port') == 22:
                techniques.add('T1021.004')
            if alert_data.get('port') == 53:
                techniques.add('T1572')

        return techniques

    def _calculate_confidence(self, techniques: Set[str]) -> float:
        """Расчёт уверенности маппинга"""
        if not techniques:
            return 0.0
        if len(techniques) >= 3:
            return 0.9
        elif len(techniques) >= 2:
            return 0.7
        else:
            return 0.5



class MITRECoverageAnalyzer:
    """Анализатор покрытия MITRE ATT&CK"""

    def __init__(self, loader: MITRELoader, logger=None):
        self.loader = loader
        self.logger = logger

        self.detected_techniques: Dict[str, int] = defaultdict(int)
        self.detected_tactics: Dict[str, int] = defaultdict(int)
        self.detection_history: deque = deque(maxlen=10000)

        self._lock = threading.RLock()

    def record_detection(self, techniques: List[str], tactics: List[str]):
        """Запись обнаружения техник"""
        with self._lock:
            for tech in techniques:
                self.detected_techniques[tech] += 1
            for tactic in tactics:
                self.detected_tactics[tactic] += 1

            self.detection_history.append({
                'timestamp': time.time(),
                'techniques': techniques,
                'tactics': tactics
            })

    def get_coverage_report(self) -> Dict:
        """Получить отчёт о покрытии"""
        with self._lock:
            total_techniques = len(self.loader.techniques)
            total_sub_techniques = len(self.loader.sub_techniques)
            total_all = total_techniques + total_sub_techniques

            detected_techs = len(self.detected_techniques)
            detected_tactics = len(self.detected_tactics)

            coverage_by_tactic = {}
            for tactic_id, tactic in self.loader.tactics.items():
                techs_in_tactic = self.loader.techniques_by_tactic.get(tactic.name, [])
                detected_in_tactic = sum(1 for t in techs_in_tactic if t in self.detected_techniques)
                coverage_by_tactic[tactic.name] = {
                    'detected': detected_in_tactic,
                    'total': len(techs_in_tactic),
                    'percentage': round(detected_in_tactic / max(1, len(techs_in_tactic)) * 100, 1)
                }

            top_techniques = sorted(
                self.detected_techniques.items(),
                key=lambda x: x[1], reverse=True
            )[:10]

            critical_techniques = ['T1003', 'T1059', 'T1021', 'T1071', 'T1048', 'T1486']
            missed_critical = [t for t in critical_techniques if t not in self.detected_techniques]

            return {
                'summary': {
                    'total_techniques': total_all,
                    'detected_techniques': detected_techs,
                    'coverage_percentage': round(detected_techs / max(1, total_all) * 100, 1),
                    'total_tactics': len(self.loader.tactics),
                    'detected_tactics': detected_tactics,
                    'tactic_coverage': round(detected_tactics / max(1, len(self.loader.tactics)) * 100, 1)
                },
                'coverage_by_tactic': coverage_by_tactic,
                'top_detected_techniques': [
                    {
                        'id': tid,
                        'name': self._get_technique_name(tid),
                        'count': count
                    }
                    for tid, count in top_techniques
                ],
                'missed_critical_techniques': [
                    {
                        'id': tid,
                        'name': self._get_technique_name(tid)
                    }
                    for tid in missed_critical
                ],
                'recommendations': self._generate_recommendations(coverage_by_tactic, missed_critical)
            }

    def _get_technique_name(self, tech_id: str) -> str:
        """Получить название техники"""
        tech = self.loader.techniques.get(tech_id) or self.loader.sub_techniques.get(tech_id)
        return tech.name if tech else tech_id

    def _generate_recommendations(self, coverage: Dict, missed_critical: List[str]) -> List[str]:
        """Генерация рекомендаций по улучшению покрытия"""
        recommendations = []

        for tactic, stats in coverage.items():
            if stats['percentage'] < 30:
                recommendations.append(f"Improve detection coverage for {tactic} (currently {stats['percentage']}%)")

        if missed_critical:
            recommendations.append(f"Implement detection for critical techniques: {', '.join(missed_critical)}")

        if not recommendations:
            recommendations.append("Coverage is good. Continue monitoring and updating detections.")

        return recommendations

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return {
                'total_detections': len(self.detection_history),
                'unique_techniques': len(self.detected_techniques),
                'unique_tactics': len(self.detected_tactics)
            }



class MITRENavigatorGenerator:
    """Генератор MITRE ATT&CK Navigator слоёв"""

    def __init__(self, loader: MITRELoader, coverage_analyzer: MITRECoverageAnalyzer, logger=None):
        self.loader = loader
        self.coverage_analyzer = coverage_analyzer
        self.logger = logger

    def generate_navigator_layer(self, name: str = "SHARD Coverage") -> Dict:
        """Генерация слоя для MITRE ATT&CK Navigator"""
        techniques = []

        for tech_id, count in self.coverage_analyzer.detected_techniques.items():
            tech = self.loader.techniques.get(tech_id) or self.loader.sub_techniques.get(tech_id)
            if tech:
                if count >= 100:
                    color = "
                elif count >= 50:
                    color = "
                elif count >= 10:
                    color = "
                else:
                    color = "

                techniques.append({
                    "techniqueID": tech_id,
                    "color": color,
                    "comment": f"Detected {count} times",
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": True
                })

        return {
            "name": name,
            "versions": {
                "attack": "15",
                "navigator": "5.1.0",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"SHARD SIEM Detection Coverage - Generated {datetime.now().isoformat()}",
            "filters": {
                "platforms": ["Windows", "Linux", "macOS", "Network", "Cloud"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": False,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {"label": ">100 detections", "color": "
                {"label": "50-100 detections", "color": "
                {"label": "10-49 detections", "color": "
                {"label": "1-9 detections", "color": "
            ],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
            "selectVisibleTechniques": False
        }

    def generate_heatmap_layer(self, name: str = "SHARD Heatmap") -> Dict:
        """Генерация тепловой карты"""
        layer = self.generate_navigator_layer(name)

        scores = []
        for tech_id, count in self.coverage_analyzer.detected_techniques.items():
            score = min(100, int(count / 2))
            layer['techniques'].append({
                "techniqueID": tech_id,
                "score": score,
                "comment": f"Score: {score}",
            })
            scores.append(score)

        if scores:
            layer['gradient'] = {
                "colors": ["
                "minValue": 0,
                "maxValue": 100
            }

        return layer



class MITREEngine:
    """
    Основной движок MITRE ATT&CK
    Объединяет загрузку, маппинг, анализ покрытия и навигатор
    """

    def __init__(self, config: MITREConfig = None, logger=None):
        self.config = config or MITREConfig()
        self.logger = logger

        self.loader = MITRELoader(self.config, logger)
        self.mapper = MITREMapper(self.loader, self.config, logger)
        self.coverage_analyzer = MITRECoverageAnalyzer(self.loader, logger)
        self.navigator_generator = MITRENavigatorGenerator(self.loader, self.coverage_analyzer, logger)

        self.stats = {
            'total_alerts_mapped': 0,
            'total_techniques_detected': 0
        }

        self._lock = threading.RLock()
        self._running = False

    def start(self):
        """Запуск движка"""
        self._running = True
        self.loader.load()

        if self.logger:
            self.logger.info("🚀 MITRE ATT&CK Engine started")

    def stop(self):
        """Остановка движка"""
        self._running = False
        if self.logger:
            self.logger.info("🛑 MITRE ATT&CK Engine stopped")

    def map_alert(self, alert: Dict) -> Dict:
        """Маппинг алерта на MITRE ATT&CK"""
        mapping = self.mapper.map_alert(alert)

        if mapping['techniques']:
            self.coverage_analyzer.record_detection(
                mapping['techniques'],
                mapping['tactics']
            )

            with self._lock:
                self.stats['total_alerts_mapped'] += 1
                self.stats['total_techniques_detected'] += len(mapping['techniques'])

        return mapping

    def get_coverage_report(self) -> Dict:
        """Получить отчёт о покрытии"""
        return self.coverage_analyzer.get_coverage_report()

    def generate_navigator_layer(self, name: str = None) -> Dict:
        """Генерация слоя для навигатора"""
        return self.navigator_generator.generate_navigator_layer(
            name or f"SHARD Coverage {datetime.now().strftime('%Y-%m-%d')}"
        )

    def save_navigator_layer(self, filepath: str = None) -> str:
        """Сохранение слоя навигатора"""
        layer = self.generate_navigator_layer()

        if not filepath:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = Path(self.config.reports_dir) / f"mitre_layer_{timestamp}.json"

        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(layer, f, indent=2)

        return str(filepath)

    def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Получить детали техники"""
        tech = self.loader.techniques.get(technique_id) or self.loader.sub_techniques.get(technique_id)
        if not tech:
            return None

        return {
            'id': tech.id,
            'name': tech.name,
            'description': tech.description,
            'tactics': tech.tactics,
            'platforms': tech.platforms,
            'permissions_required': tech.permissions_required,
            'data_sources': tech.data_sources,
            'detection_recommendations': tech.detection_recommendations,
            'sub_techniques': tech.sub_techniques,
            'parent_technique': tech.parent_technique,
            'groups': self.loader.groups_by_technique.get(technique_id, []),
            'software': self.loader.software_by_technique.get(technique_id, []),
            'mitigations': self.loader.mitigations_by_technique.get(technique_id, []),
            'detection_count': self.coverage_analyzer.detected_techniques.get(technique_id, 0)
        }

    def get_tactic_details(self, tactic_name: str) -> Optional[Dict]:
        """Получить детали тактики"""
        for tactic in self.loader.tactics.values():
            if tactic.name == tactic_name or tactic.short_name == tactic_name:
                techniques = self.loader.techniques_by_tactic.get(tactic.name, [])
                return {
                    'id': tactic.id,
                    'name': tactic.name,
                    'short_name': tactic.short_name,
                    'description': tactic.description,
                    'techniques_count': len(techniques),
                    'techniques': techniques,
                    'detected_count': sum(1 for t in techniques if t in self.coverage_analyzer.detected_techniques)
                }
        return None

    def search(self, query: str) -> List[Dict]:
        """Поиск по техникам, тактикам, группам"""
        results = []
        query_lower = query.lower()

        for tech_id, tech in self.loader.techniques.items():
            if query_lower in tech.name.lower() or query_lower in tech_id.lower():
                results.append({
                    'type': 'technique',
                    'id': tech_id,
                    'name': tech.name,
                    'description': tech.description[:200]
                })

        for tactic in self.loader.tactics.values():
            if query_lower in tactic.name.lower() or query_lower in tactic.short_name.lower():
                results.append({
                    'type': 'tactic',
                    'id': tactic.id,
                    'name': tactic.name,
                    'short_name': tactic.short_name
                })

        for group in self.loader.groups.values():
            if query_lower in group.name.lower() or any(query_lower in a.lower() for a in group.aliases):
                results.append({
                    'type': 'group',
                    'id': group.id,
                    'name': group.name,
                    'aliases': group.aliases
                })

        return results[:50]

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return {
                **self.stats,
                'coverage_stats': self.coverage_analyzer.get_stats(),
                'total_techniques_loaded': len(self.loader.techniques),
                'total_sub_techniques_loaded': len(self.loader.sub_techniques),
                'total_tactics_loaded': len(self.loader.tactics)
            }



class ShardMITREIntegration:
    """Интеграция MITRE ATT&CK в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = MITREConfig()
        self.engine: Optional[MITREEngine] = None
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger):
        """Настройка интеграции"""
        self.event_bus = event_bus
        self.logger = logger
        self.engine = MITREEngine(self.config, logger)

        if event_bus:
            event_bus.subscribe('alert.detected', self.on_alert)
            event_bus.subscribe('mitre.search', self.on_search_request)
            event_bus.subscribe('mitre.coverage', self.on_coverage_request)

    def start(self):
        """Запуск интеграции"""
        if self.engine:
            self.engine.start()

        if self.logger:
            self.logger.info("🚀 MITRE ATT&CK Integration запущена")

    def stop(self):
        """Остановка интеграции"""
        if self.engine:
            self.engine.stop()

    def on_alert(self, alert: Dict):
        """Обогащение алерта MITRE данными"""
        if self.engine:
            mapping = self.engine.map_alert(alert)
            alert['mitre_mapping'] = mapping

            if self.event_bus:
                self.event_bus.publish('alert.enriched', alert)

    def on_search_request(self, data: Dict):
        """Обработка поискового запроса"""
        query = data.get('query', '')

        if query and self.engine:
            results = self.engine.search(query)

            if self.event_bus:
                self.event_bus.publish('mitre.search.results', {
                    'query': query,
                    'results': results,
                    'request_id': data.get('request_id')
                })

    def on_coverage_request(self, data: Dict):
        """Обработка запроса покрытия"""
        if self.engine:
            report = self.engine.get_coverage_report()

            if self.event_bus:
                self.event_bus.publish('mitre.coverage.report', {
                    'report': report,
                    'request_id': data.get('request_id')
                })

    def get_coverage_report(self) -> Dict:
        """Получить отчёт о покрытии"""
        if self.engine:
            return self.engine.get_coverage_report()
        return {}

    def generate_navigator_layer(self) -> str:
        """Генерация слоя для навигатора"""
        if self.engine:
            return self.engine.save_navigator_layer()
        return ""

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Получить информацию о технике"""
        if self.engine:
            return self.engine.get_technique_details(technique_id)
        return None

    def search(self, query: str) -> List[Dict]:
        """Поиск по MITRE"""
        if self.engine:
            return self.engine.search(query)
        return []

    def get_stats(self) -> Dict:
        """Получить статистику"""
        if self.engine:
            return self.engine.get_stats()
        return {}



def test_mitre():
    """Тестирование MITRE ATT&CK"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ MITRE ATT&CK FULL COVERAGE")
    print("=" * 60)

    config = MITREConfig()
    engine = MITREEngine(config)
    engine.start()

    print("\n📝 Тест 1: Маппинг алерта")
    test_alert = {
        'attack_type': 'Brute Force',
        'severity': 'HIGH',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.5',
        'dst_port': 22,
        'explanation': 'Multiple failed SSH login attempts detected'
    }
    mapping = engine.map_alert(test_alert)
    print(f"   Tactics: {mapping['tactics']}")
    print(f"   Techniques: {mapping['techniques']}")
    print(f"   Confidence: {mapping['confidence']}")

    print("\n📝 Тест 2: Отчёт о покрытии")
    coverage = engine.get_coverage_report()
    summary = coverage['summary']
    print(f"   Coverage: {summary['coverage_percentage']}%")
    print(f"   Detected techniques: {summary['detected_techniques']}/{summary['total_techniques']}")

    print("\n📝 Тест 3: Детали техники T1110")
    details = engine.get_technique_details('T1110')
    if details:
        print(f"   Name: {details['name']}")
        print(f"   Detection count: {details['detection_count']}")

    print("\n📝 Тест 4: Поиск 'PowerShell'")
    results = engine.search('PowerShell')
    for r in results[:3]:
        print(f"   - [{r['type']}] {r['id']}: {r['name']}")

    print("\n📝 Тест 5: Генерация слоя навигатора")
    layer_path = engine.save_navigator_layer()
    print(f"   Saved to: {layer_path}")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_mitre()
#!/usr/bin/env python3

"""
SHARD SOAR Integration Module
Security Orchestration, Automation and Response
Интеграция с TheHive, Shuffle, n8n и встроенные playbooks

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import re
import json
import time
import threading
import hashlib
import base64
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union, Callable
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml


class PlaybookStatus(Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ActionType(Enum):
    NOTIFICATION = "notification"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    ENRICH_ALERT = "enrich_alert"
    CREATE_TICKET = "create_ticket"
    RUN_SCRIPT = "run_script"
    WEBHOOK = "webhook"
    WAIT = "wait"
    CONDITION = "condition"
    PARALLEL = "parallel"


@dataclass
class SOARConfig:

    thehive_enabled: bool = False
    thehive_url: str = "http://localhost:9000"
    thehive_api_key: str = ""

    shuffle_enabled: bool = False
    shuffle_url: str = "http://localhost:3001"
    shuffle_api_key: str = ""

    n8n_enabled: bool = False
    n8n_url: str = "http://localhost:5678"
    n8n_api_key: str = ""

    slack_enabled: bool = False
    slack_webhook: str = ""

    teams_enabled: bool = False
    teams_webhook: str = ""

    playbooks_dir: str = "./data/soar/playbooks/"
    auto_execute_playbooks: bool = True

    max_concurrent_playbooks: int = 10
    max_actions_per_playbook: int = 50
    action_timeout: int = 300

    db_path: str = "./data/soar/soar.db"


class BaseAction:

    def __init__(self, name: str, config: Dict, logger=None):
        self.name = name
        self.config = config
        self.logger = logger

    def execute(self, context: Dict) -> Dict:
        raise NotImplementedError

    def rollback(self, context: Dict) -> Dict:
        return {'status': 'not_implemented'}


class BlockIPAction(BaseAction):

    def __init__(self, config: Dict, logger=None):
        super().__init__("block_ip", config, logger)
        self.firewall = None

    def execute(self, context: Dict) -> Dict:
        ip = context.get('ip') or context.get('alert', {}).get('src_ip')
        duration = self.config.get('duration', 3600)

        if not ip:
            return {'status': 'failed', 'error': 'No IP provided'}

        if self.logger:
            self.logger.info(f"🛡️ Blocking IP: {ip} for {duration}s")

        try:
            if self.firewall:
                result = self.firewall.block_ip(ip, duration)
                return {'status': 'completed', 'ip': ip, 'duration': duration, 'result': result}
            else:
                cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(cmd, capture_output=True, check=False)
                return {'status': 'completed', 'ip': ip, 'duration': duration}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

    def rollback(self, context: Dict) -> Dict:
        ip = context.get('ip')
        if ip:
            try:
                cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(cmd, capture_output=True, check=False)
                return {'status': 'completed', 'ip': ip}
            except Exception as e:
                return {'status': 'failed', 'error': str(e)}
        return {'status': 'failed', 'error': 'No IP'}


class IsolateHostAction(BaseAction):

    def execute(self, context: Dict) -> Dict:
        host = context.get('host') or context.get('alert', {}).get('dst_ip')

        if not host:
            return {'status': 'failed', 'error': 'No host provided'}

        if self.logger:
            self.logger.warning(f"🔒 Isolating host: {host}")

        try:
            cmds = [
                ['iptables', '-A', 'INPUT', '-s', host, '-j', 'DROP'],
                ['iptables', '-A', 'OUTPUT', '-d', host, '-j', 'DROP'],
                ['iptables', '-A', 'FORWARD', '-s', host, '-j', 'DROP'],
                ['iptables', '-A', 'FORWARD', '-d', host, '-j', 'DROP']
            ]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, check=False)

            return {'status': 'completed', 'host': host}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}


class NotificationAction(BaseAction):

    def __init__(self, config: Dict, logger=None):
        super().__init__("notification", config, logger)
        self.slack_webhook = config.get('slack_webhook', '')
        self.teams_webhook = config.get('teams_webhook', '')

    def execute(self, context: Dict) -> Dict:
        message = self.config.get('message', 'Alert triggered')
        severity = context.get('alert', {}).get('severity', 'INFO')

        formatted_message = message.format(**context)

        results = {}

        if self.config.get('slack', False) and self.slack_webhook:
            try:
                color = {'CRITICAL': '
                                                                                                              '
                payload = {
                    'attachments': [{
                        'color': color,
                        'title': f'🚨 SHARD Alert: {severity}',
                        'text': formatted_message,
                        'fields': [
                            {'title': 'Source', 'value': context.get('alert', {}).get('src_ip', 'N/A'), 'short': True},
                            {'title': 'Target', 'value': context.get('alert', {}).get('dst_ip', 'N/A'), 'short': True},
                            {'title': 'Attack Type', 'value': context.get('alert', {}).get('attack_type', 'N/A'),
                             'short': True},
                        ],
                        'ts': int(time.time())
                    }]
                }
                response = requests.post(self.slack_webhook, json=payload, timeout=10)
                results['slack'] = {'status': 'sent' if response.status_code == 200 else 'failed'}
            except Exception as e:
                results['slack'] = {'status': 'failed', 'error': str(e)}

        if self.config.get('teams', False) and self.teams_webhook:
            try:
                payload = {
                    '@type': 'MessageCard',
                    '@context': 'http://schema.org/extensions',
                    'themeColor': '0076D7',
                    'summary': f'SHARD Alert: {severity}',
                    'title': f'🚨 SHARD Alert: {severity}',
                    'text': formatted_message,
                    'sections': [{
                        'facts': [
                            {'name': 'Source', 'value': context.get('alert', {}).get('src_ip', 'N/A')},
                            {'name': 'Target', 'value': context.get('alert', {}).get('dst_ip', 'N/A')},
                            {'name': 'Attack Type', 'value': context.get('alert', {}).get('attack_type', 'N/A')}
                        ]
                    }]
                }
                response = requests.post(self.teams_webhook, json=payload, timeout=10)
                results['teams'] = {'status': 'sent' if response.status_code == 200 else 'failed'}
            except Exception as e:
                results['teams'] = {'status': 'failed', 'error': str(e)}

        if self.logger:
            self.logger.info(f"📢 Notification sent: {formatted_message[:100]}")

        return {'status': 'completed', 'results': results}


class EnrichAlertAction(BaseAction):

    def execute(self, context: Dict) -> Dict:
        alert = context.get('alert', {})
        enriched = alert.copy()

        ip = alert.get('src_ip')
        if ip and not ip.startswith(('192.168.', '10.', '172.', '127.')):
            try:
                response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
                if response.status_code == 200:
                    geo = response.json()
                    enriched['geo'] = {
                        'country': geo.get('country'),
                        'city': geo.get('city'),
                        'isp': geo.get('isp'),
                        'lat': geo.get('lat'),
                        'lon': geo.get('lon')
                    }
            except:
                pass

        abuse_key = self.config.get('abuseipdb_key')
        if abuse_key and ip:
            try:
                headers = {'Key': abuse_key, 'Accept': 'application/json'}
                response = requests.get(f'https://api.abuseipdb.com/api/v2/check',
                                        params={'ipAddress': ip, 'maxAgeInDays': 90},
                                        headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    enriched['threat_intel'] = {
                        'abuse_score': data.get('abuseConfidenceScore', 0),
                        'total_reports': data.get('totalReports', 0),
                        'country': data.get('countryCode'),
                        'isp': data.get('isp')
                    }
            except:
                pass

        context['enriched_alert'] = enriched

        if self.logger:
            self.logger.info(f"🔍 Alert enriched for {ip}")

        return {'status': 'completed', 'enriched': bool(context.get('enriched_alert'))}


class CreateTicketAction(BaseAction):

    def __init__(self, config: Dict, logger=None):
        super().__init__("create_ticket", config, logger)
        self.thehive_url = config.get('thehive_url', '')
        self.thehive_api_key = config.get('thehive_api_key', '')

    def execute(self, context: Dict) -> Dict:
        if not self.thehive_url or not self.thehive_api_key:
            return {'status': 'failed', 'error': 'TheHive not configured'}

        alert = context.get('enriched_alert', context.get('alert', {}))

        ticket = {
            'title': f"[SHARD] {alert.get('attack_type', 'Unknown')} from {alert.get('src_ip', 'unknown')}",
            'description': self._format_description(alert),
            'type': 'external',
            'source': 'SHARD SIEM',
            'sourceRef': alert.get('id', str(int(time.time()))),
            'severity': self._map_severity(alert.get('severity', 'MEDIUM')),
            'tags': ['shard', alert.get('attack_type', 'unknown').lower().replace(' ', '_')],
            'customFields': {
                'src_ip': {'string': alert.get('src_ip', '')},
                'dst_ip': {'string': alert.get('dst_ip', '')},
                'score': {'number': alert.get('score', 0)}
            }
        }

        try:
            headers = {
                'Authorization': f'Bearer {self.thehive_api_key}',
                'Content-Type': 'application/json'
            }
            response = requests.post(f'{self.thehive_url}/api/v1/alert',
                                     json=ticket, headers=headers, timeout=10)

            if response.status_code in [200, 201]:
                result = response.json()
                if self.logger:
                    self.logger.info(f"📋 Ticket created in TheHive: {result.get('id')}")
                return {'status': 'completed', 'ticket_id': result.get('id')}
            else:
                return {'status': 'failed', 'error': f'HTTP {response.status_code}'}

        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

    def _format_description(self, alert: Dict) -> str:
        lines = [
            f"**Alert Type:** {alert.get('attack_type', 'Unknown')}",
            f"**Severity:** {alert.get('severity', 'MEDIUM')}",
            f"**Score:** {alert.get('score', 0):.2f}",
            f"**Confidence:** {alert.get('confidence', 0):.0%}",
            "",
            f"**Source IP:** {alert.get('src_ip', 'N/A')}",
            f"**Destination IP:** {alert.get('dst_ip', 'N/A')}",
            f"**Port:** {alert.get('dst_port', 'N/A')}",
            "",
        ]

        if alert.get('explanation'):
            lines.append(f"**Explanation:** {alert['explanation']}")

        if alert.get('geo'):
            geo = alert['geo']
            lines.append(f"**Location:** {geo.get('city')}, {geo.get('country')} ({geo.get('isp')})")

        if alert.get('threat_intel'):
            ti = alert['threat_intel']
            lines.append(f"**AbuseIPDB Score:** {ti.get('abuse_score', 0)}% ({ti.get('total_reports', 0)} reports)")

        return '\n'.join(lines)

    def _map_severity(self, severity: str) -> int:
        return {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(severity, 2)


class WebhookAction(BaseAction):

    def execute(self, context: Dict) -> Dict:
        url = self.config.get('url')
        method = self.config.get('method', 'POST')
        headers = self.config.get('headers', {})

        if not url:
            return {'status': 'failed', 'error': 'No URL provided'}

        body_template = self.config.get('body', {})
        body = self._interpolate(body_template, context)

        try:
            if method.upper() == 'GET':
                response = requests.get(url, params=body, headers=headers, timeout=30)
            elif method.upper() == 'POST':
                response = requests.post(url, json=body, headers=headers, timeout=30)
            elif method.upper() == 'PUT':
                response = requests.put(url, json=body, headers=headers, timeout=30)
            else:
                return {'status': 'failed', 'error': f'Unsupported method: {method}'}

            return {
                'status': 'completed',
                'response_code': response.status_code,
                'response_body': response.text[:1000]
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}

    def _interpolate(self, obj: Any, context: Dict) -> Any:
        if isinstance(obj, dict):
            return {k: self._interpolate(v, context) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._interpolate(v, context) for v in obj]
        elif isinstance(obj, str):
            result = obj
            for match in re.finditer(r'\{([^}]+)\}', obj):
                path = match.group(1)
                value = self._get_nested(context, path)
                result = result.replace(match.group(0), str(value))
            return result
        else:
            return obj

    def _get_nested(self, obj: Dict, path: str) -> Any:
        keys = path.split('.')
        value = obj
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return ''
        return value or ''


class ConditionAction(BaseAction):

    def execute(self, context: Dict) -> Dict:
        condition = self.config.get('condition', '')
        true_branch = self.config.get('true', [])
        false_branch = self.config.get('false', [])

        result = self._evaluate(condition, context)

        return {
            'status': 'completed',
            'result': result,
            'next_actions': true_branch if result else false_branch
        }

    def _evaluate(self, condition: str, context: Dict) -> bool:
        try:
            for match in re.finditer(r'([\w\.]+)', condition):
                path = match.group(1)
                if '.' in path:
                    value = self._get_nested(context, path)
                    if isinstance(value, str):
                        condition = condition.replace(path, f"'{value}'")
                    else:
                        condition = condition.replace(path, str(value))

            allowed_names = {'True': True, 'False': False, 'None': None}
            return eval(condition, {"__builtins__": {}}, allowed_names)
        except:
            return False

    def _get_nested(self, obj: Dict, path: str) -> Any:
        keys = path.split('.')
        value = obj
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value


class Playbook:

    def __init__(self, playbook_id: str, name: str, config: Dict, actions: List[BaseAction]):
        self.id = playbook_id
        self.name = name
        self.config = config
        self.actions = actions
        self.triggers = config.get('triggers', [])
        self.enabled = config.get('enabled', True)
        self.status = PlaybookStatus.PENDING
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.results: List[Dict] = []
        self.context: Dict = {}
        self.error: Optional[str] = None

    def execute(self, initial_context: Dict) -> Dict:
        self.status = PlaybookStatus.RUNNING
        self.start_time = time.time()
        self.context = initial_context.copy()
        self.results = []

        try:
            for i, action in enumerate(self.actions):
                if not isinstance(action, BaseAction):
                    continue

                action_result = action.execute(self.context)
                self.results.append({
                    'index': i,
                    'action': action.name,
                    'result': action_result
                })

                self.context[f'action_{i}_result'] = action_result

                if isinstance(action, ConditionAction):
                    next_actions = action_result.get('next_actions', [])
                    if next_actions:
                        for next_idx in next_actions:
                            if next_idx < len(self.actions):
                                branch_action = self.actions[next_idx]
                                branch_result = branch_action.execute(self.context)
                                self.results.append({
                                    'index': next_idx,
                                    'action': branch_action.name,
                                    'result': branch_result,
                                    'branch': True
                                })

                if action_result.get('status') == 'failed' and self.config.get('stop_on_error', True):
                    self.status = PlaybookStatus.FAILED
                    self.error = action_result.get('error', 'Unknown error')
                    break

            if self.status == PlaybookStatus.RUNNING:
                self.status = PlaybookStatus.COMPLETED

        except Exception as e:
            self.status = PlaybookStatus.FAILED
            self.error = str(e)

        self.end_time = time.time()

        return {
            'playbook_id': self.id,
            'playbook_name': self.name,
            'status': self.status.value,
            'duration': self.end_time - self.start_time if self.start_time else 0,
            'results': self.results,
            'error': self.error
        }

    def should_trigger(self, alert: Dict) -> bool:
        if not self.enabled:
            return False

        for trigger in self.triggers:
            if self._match_trigger(trigger, alert):
                return True

        return False

    def _match_trigger(self, trigger: Dict, alert: Dict) -> bool:
        trigger_type = trigger.get('type')

        if trigger_type == 'attack_type':
            return alert.get('attack_type') in trigger.get('values', [])
        elif trigger_type == 'severity':
            return alert.get('severity') in trigger.get('values', [])
        elif trigger_type == 'score':
            score = alert.get('score', 0)
            min_score = trigger.get('min', 0)
            max_score = trigger.get('max', 1)
            return min_score <= score <= max_score
        elif trigger_type == 'always':
            return True

        return False


class PlaybookLoader:

    def __init__(self, config: SOARConfig, logger=None):
        self.config = config
        self.logger = logger
        self.action_factory = ActionFactory(config, logger)

    def load_all(self) -> List[Playbook]:
        playbooks = []
        playbooks_dir = Path(self.config.playbooks_dir)

        if playbooks_dir.exists():
            for pb_file in playbooks_dir.glob('*.yml'):
                try:
                    with open(pb_file, 'r') as f:
                        pb_config = yaml.safe_load(f)
                        playbook = self._parse_playbook(pb_config, pb_file.stem)
                        if playbook:
                            playbooks.append(playbook)
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error loading playbook {pb_file}: {e}")

        if not playbooks:
            playbooks = self._create_embedded_playbooks()

        return playbooks

    def _parse_playbook(self, config: Dict, playbook_id: str) -> Optional[Playbook]:
        name = config.get('name', playbook_id)
        actions = []

        for action_config in config.get('actions', []):
            action = self.action_factory.create_action(action_config)
            if action:
                actions.append(action)

        return Playbook(
            playbook_id=playbook_id,
            name=name,
            config=config,
            actions=actions
        )

    def _create_embedded_playbooks(self) -> List[Playbook]:
        playbooks = []

        pb1_config = {
            'name': 'Critical Alert Response',
            'enabled': True,
            'triggers': [
                {'type': 'severity', 'values': ['CRITICAL']}
            ],
            'stop_on_error': False
        }
        pb1_actions = [
            self.action_factory.create_action({'type': 'enrich_alert'}),
            self.action_factory.create_action({'type': 'notification', 'slack': True,
                                               'message': '🚨 CRITICAL alert: {alert.attack_type} from {alert.src_ip}'}),
            self.action_factory.create_action({'type': 'block_ip', 'duration': 86400}),
            self.action_factory.create_action({'type': 'create_ticket'}),
        ]
        playbooks.append(Playbook('embedded_critical', 'Critical Alert Response', pb1_config, pb1_actions))

        pb2_config = {
            'name': 'High Alert Response',
            'enabled': True,
            'triggers': [
                {'type': 'severity', 'values': ['HIGH']}
            ]
        }
        pb2_actions = [
            self.action_factory.create_action({'type': 'enrich_alert'}),
            self.action_factory.create_action({'type': 'notification', 'slack': True,
                                               'message': '⚠️ HIGH alert: {alert.attack_type} from {alert.src_ip}'}),
            self.action_factory.create_action({'type': 'block_ip', 'duration': 3600}),
        ]
        playbooks.append(Playbook('embedded_high', 'High Alert Response', pb2_config, pb2_actions))

        pb3_config = {
            'name': 'Brute Force Response',
            'enabled': True,
            'triggers': [
                {'type': 'attack_type', 'values': ['Brute Force']}
            ]
        }
        pb3_actions = [
            self.action_factory.create_action(
                {'type': 'notification', 'message': '🔐 Brute force detected from {alert.src_ip}'}),
            self.action_factory.create_action({'type': 'block_ip', 'duration': 7200}),
        ]
        playbooks.append(Playbook('embedded_bruteforce', 'Brute Force Response', pb3_config, pb3_actions))

        return playbooks


class ActionFactory:

    def __init__(self, config: SOARConfig, logger=None):
        self.config = config
        self.logger = logger

    def create_action(self, action_config: Dict) -> Optional[BaseAction]:
        action_type = action_config.get('type')

        if action_type == 'block_ip':
            return BlockIPAction(action_config, self.logger)
        elif action_type == 'isolate_host':
            return IsolateHostAction(action_config, self.logger)
        elif action_type == 'notification':
            action_config.setdefault('slack_webhook', self.config.slack_webhook)
            action_config.setdefault('teams_webhook', self.config.teams_webhook)
            return NotificationAction(action_config, self.logger)
        elif action_type == 'enrich_alert':
            return EnrichAlertAction(action_config, self.logger)
        elif action_type == 'create_ticket':
            action_config.setdefault('thehive_url', self.config.thehive_url)
            action_config.setdefault('thehive_api_key', self.config.thehive_api_key)
            return CreateTicketAction(action_config, self.logger)
        elif action_type == 'webhook':
            return WebhookAction(action_config, self.logger)
        elif action_type == 'condition':
            return ConditionAction(action_config, self.logger)
        else:
            if self.logger:
                self.logger.warning(f"Unknown action type: {action_type}")
            return None


class SOAREngine:

    def __init__(self, config: SOARConfig = None, logger=None):
        self.config = config or SOARConfig()
        self.logger = logger

        self.playbooks: Dict[str, Playbook] = {}
        self.execution_history: deque = deque(maxlen=1000)
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_concurrent_playbooks)

        self.stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'actions_executed': 0
        }

        self._lock = threading.RLock()
        self._running = False

        self._load_playbooks()

    def _load_playbooks(self):
        loader = PlaybookLoader(self.config, self.logger)
        for pb in loader.load_all():
            self.playbooks[pb.id] = pb

        if self.logger:
            self.logger.info(f"✅ Loaded {len(self.playbooks)} playbooks")

    def start(self):
        self._running = True
        if self.logger:
            self.logger.info("🚀 SOAR Engine started")

    def stop(self):
        self._running = False
        self.executor.shutdown(wait=True, timeout=30)
        if self.logger:
            self.logger.info("🛑 SOAR Engine stopped")

    def on_alert(self, alert: Dict) -> List[str]:
        triggered_playbooks = []

        for pb_id, pb in self.playbooks.items():
            if pb.should_trigger(alert):
                triggered_playbooks.append(pb_id)

                if self.config.auto_execute_playbooks:
                    self.execute_playbook_async(pb_id, {'alert': alert})

        if triggered_playbooks and self.logger:
            self.logger.info(
                f"🎯 Alert triggered {len(triggered_playbooks)} playbooks: {', '.join(triggered_playbooks)}")

        return triggered_playbooks

    def execute_playbook_async(self, playbook_id: str, context: Dict) -> str:
        execution_id = f"exec_{int(time.time())}_{hash(str(context)) % 10000}"

        def run():
            result = self.execute_playbook(playbook_id, context)
            with self._lock:
                self.execution_history.append({
                    'execution_id': execution_id,
                    'playbook_id': playbook_id,
                    'timestamp': time.time(),
                    'result': result
                })

        self.executor.submit(run)
        return execution_id

    def execute_playbook(self, playbook_id: str, context: Dict) -> Dict:
        pb = self.playbooks.get(playbook_id)
        if not pb:
            return {'status': 'failed', 'error': f'Playbook {playbook_id} not found'}

        if self.logger:
            self.logger.info(f"📋 Executing playbook: {pb.name}")

        with self._lock:
            self.stats['total_executions'] += 1

        result = pb.execute(context)

        with self._lock:
            self.stats['actions_executed'] += len(result.get('results', []))
            if result.get('status') == 'COMPLETED':
                self.stats['successful_executions'] += 1
            else:
                self.stats['failed_executions'] += 1

        if self.logger:
            self.logger.info(f"📋 Playbook {pb.name} completed: {result.get('status')}")

        return result

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self.playbooks.get(playbook_id)

    def list_playbooks(self) -> List[Dict]:
        return [
            {
                'id': pb.id,
                'name': pb.name,
                'enabled': pb.enabled,
                'triggers': pb.triggers,
                'actions_count': len(pb.actions)
            }
            for pb in self.playbooks.values()
        ]

    def get_stats(self) -> Dict:
        with self._lock:
            return dict(self.stats)

    def get_execution_history(self, limit: int = 20) -> List[Dict]:
        return list(self.execution_history)[-limit:]


class ShardSOARIntegration:

    def __init__(self, config: Dict = None):
        self.config = SOARConfig()
        self.engine: Optional[SOAREngine] = None
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger, firewall=None):
        self.event_bus = event_bus
        self.logger = logger
        self.engine = SOAREngine(self.config, logger)

        if firewall:
            pass

        if event_bus:
            event_bus.subscribe('alert.detected', self.on_alert)
            event_bus.subscribe('soar.execute', self.on_execute_request)

    def start(self):
        if self.engine:
            self.engine.start()

        if self.logger:
            self.logger.info("🚀 SOAR Integration запущена")

    def stop(self):
        if self.engine:
            self.engine.stop()

    def on_alert(self, alert: Dict):
        if self.engine:
            self.engine.on_alert(alert)

    def on_execute_request(self, data: Dict):
        playbook_id = data.get('playbook_id')
        context = data.get('context', {})

        if playbook_id and self.engine:
            result = self.engine.execute_playbook(playbook_id, context)

            if self.event_bus:
                self.event_bus.publish('soar.execution.completed', {
                    'playbook_id': playbook_id,
                    'result': result,
                    'request_id': data.get('request_id')
                })

    def execute_playbook(self, playbook_id: str, context: Dict) -> Dict:
        if self.engine:
            return self.engine.execute_playbook(playbook_id, context)
        return {'status': 'failed', 'error': 'Engine not initialized'}

    def list_playbooks(self) -> List[Dict]:
        if self.engine:
            return self.engine.list_playbooks()
        return []

    def get_stats(self) -> Dict:
        if self.engine:
            return self.engine.get_stats()
        return {}


def test_soar():
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ SOAR INTEGRATION")
    print("=" * 60)

    config = SOARConfig()
    config.auto_execute_playbooks = True

    engine = SOAREngine(config)
    engine.start()

    print(f"\n📝 Тест 1: Playbooks ({len(engine.playbooks)})")
    for pb in engine.list_playbooks():
        print(f"   - {pb['name']} (actions: {pb['actions_count']}, triggers: {len(pb['triggers'])})")

    print("\n📝 Тест 2: Выполнение playbook")
    test_alert = {
        'attack_type': 'Brute Force',
        'severity': 'CRITICAL',
        'score': 0.85,
        'confidence': 0.9,
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.5',
        'dst_port': 22,
        'explanation': 'Multiple failed SSH login attempts'
    }

    triggered = engine.on_alert(test_alert)
    print(f"   Triggered playbooks: {triggered}")

    time.sleep(2)

    print("\n📝 Тест 3: Статистика")
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n📝 Тест 4: История выполнений")
    history = engine.get_execution_history(5)
    for h in history:
        result = h.get('result', {})
        print(f"   {h['playbook_id']}: {result.get('status')} ({result.get('duration', 0):.2f}s)")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_soar()
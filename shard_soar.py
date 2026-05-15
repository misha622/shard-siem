#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHARD SOAR Integration — оркестрация реагирования на инциденты
"""

from typing import Dict, List, Optional, Any


class ShardSOARIntegration:
    """SOAR (Security Orchestration Automation and Response) Integration"""
    
    def __init__(self):
        self.playbooks = [
            {
                'id': 'block_ip',
                'name': 'Block IP',
                'description': 'Автоматическая блокировка IP адреса через firewall'
            },
            {
                'id': 'isolate_host',
                'name': 'Isolate Host',
                'description': 'Изоляция хоста в сети через EDR'
            },
            {
                'id': 'collect_forensics',
                'name': 'Collect Forensics',
                'description': 'Сбор цифровых доказательств с хоста'
            },
            {
                'id': 'notify_admin',
                'name': 'Notify Admin',
                'description': 'Уведомление администратора через email/telegram'
            },
            {
                'id': 'block_domain',
                'name': 'Block Domain',
                'description': 'Блокировка домена через DNS фильтрацию'
            },
        ]
        self.event_bus = None
        self.logger = None
        self.firewall = None
        self._running = False
    
    def setup(self, event_bus, logger, firewall=None):
        self.event_bus = event_bus
        self.logger = logger
        self.firewall = firewall
        if self.logger:
            self.logger.info("SOAR Integration initialized")
    
    def start(self):
        self._running = True
        if self.logger:
            self.logger.info("SOAR Integration started")
    
    def stop(self):
        self._running = False
        if self.logger:
            self.logger.info("SOAR Integration stopped")
    
    def execute_playbook(self, playbook_id: str, context: Dict) -> Dict:
        """Выполнить playbook по ID"""
        playbook = self._find_playbook(playbook_id)
        if not playbook:
            return {'status': 'failed', 'error': f'Playbook {playbook_id} not found'}
        
        result = {'status': 'success', 'playbook': playbook['name'], 'actions': []}
        
        if playbook_id == 'block_ip':
            ip = context.get('ip') or context.get('src_ip')
            if ip and self.firewall:
                self.firewall.block_ip(ip)
                result['actions'].append(f'IP {ip} blocked')
        
        elif playbook_id == 'notify_admin':
            message = context.get('message', 'Security alert from SHARD')
            if self.event_bus:
                self.event_bus.publish('notification.send', {'message': message})
                result['actions'].append('Admin notified')
        
        return result
    
    def list_playbooks(self) -> List[Dict]:
        """Список всех playbooks"""
        return [{'id': p['id'], 'name': p['name'], 'description': p['description']} 
                for p in self.playbooks]
    
    def _find_playbook(self, playbook_id: str) -> Optional[Dict]:
        for p in self.playbooks:
            if p['id'] == playbook_id:
                return p
        return None

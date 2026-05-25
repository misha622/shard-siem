#!/usr/bin/env python3
"""SHARD SmartFirewall Module - Production Ready Version"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import os
import time
import threading
import re
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, Future


class SmartFirewall(BaseModule):
    """Умный файрвол с градацией ответа и асинхронным применением правил"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Firewall", config, event_bus, logger)
        self.auto_block = config.get('protection.auto_block', False)
        self.block_duration = config.get('protection.block_duration', 3600)
        self.rate_threshold = config.get('protection.rate_limit.threshold', 100)
        self.rate_window = config.get('protection.rate_limit.window', 60)
        self.max_rate_entries = config.get('protection.rate_limit.max_entries', 10000)
        self.max_ips_tracked = config.get('protection.rate_limit.max_ips', 5000)

        # Rate limiting with bounded memory
        self.rate_limits: Dict[str, Dict[int, deque]] = {}
        self._rate_entries_count = 0

        # Blocking state
        self.blocked_ips: Dict[str, float] = {}
        self.pending_blocks: Set[str] = set()  # IPs currently being blocked by external commands
        self.blocked_ports: Dict[str, Set[int]] = defaultdict(set)
        self.action_levels: Dict[str, int] = defaultdict(int)
        self.action_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self.last_activity: Dict[str, float] = {}  # Track last activity for cleanup
        self.whitelist: Set[str] = set()

        self.response_levels = {
            1: 'throttle',
            2: 'block_port',
            3: 'block_ip_temp',
            4: 'block_ip_perm'
        }

        # Thread safety
        self._lock = threading.RLock()
        self._rate_lock = threading.RLock()

        # Async executor for system commands (non-blocking firewall operations)
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fw-cmd")
        self._pending_futures: List[Future] = []

        # iptables chain status
        self._chain_created = False

        # Ensure data directory exists
        Path('data').mkdir(parents=True, exist_ok=True)
        Path('logs').mkdir(parents=True, exist_ok=True)

        # Subscribe to events
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('exfiltration.detected', self.on_exfiltration)

    def _load_counters(self) -> None:
        """Restore block counters after restart"""
        try:
            path = Path('data/block_counters.json')
            if path.exists():
                with open(path, 'r') as f:
                    data = json.load(f)
                    if time.time() - data.get('timestamp', 0) < 86400:
                        with self._lock:
                            self.action_levels.update(data.get('action_levels', {}))
                            blocked_data = data.get('blocked_ips', {})
                            for ip, expiry in blocked_data.items():
                                if time.time() < expiry:
                                    self.blocked_ips[ip] = expiry
        except Exception as e:
            self.logger.warning(f"Failed to load block counters: {e}")

    def _save_counters(self) -> None:
        """Save block counters between restarts"""
        try:
            with self._lock:
                counters_data = {
                    'action_levels': dict(self.action_levels),
                    'blocked_ips': dict(self.blocked_ips),
                    'timestamp': time.time()
                }

            with open('data/block_counters.json', 'w') as f:
                json.dump(counters_data, f)
        except Exception as e:
            self.logger.warning(f"Failed to save block counters: {e}")

    def start(self) -> None:
        """Start the firewall module"""
        self.running = True
        self._load_counters()

        # Initialize firewall chain if needed
        if os.name != 'nt':
            self._executor.submit(self.add_iptables_chain)

        # Start cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True, name="fw-cleanup").start()

        self.logger.info(f"Firewall started (auto_block: {self.auto_block}, smart mode)")

    def stop(self) -> None:
        """Stop the firewall module gracefully"""
        self.running = False

        # Wait for pending operations
        for future in self._pending_futures:
            try:
                future.result(timeout=5)
            except Exception:
                pass

        self._save_counters()
        self._executor.shutdown(wait=True, cancel_futures=False)
        self.logger.info("Firewall stopped")

    def add_to_whitelist(self, ip: str) -> None:
        """Add IP to whitelist"""
        if not self._validate_ip(ip):
            return
        with self._lock:
            self.whitelist.add(ip)
            # Remove any existing blocks for this IP
            self._unblock_ip_internal(ip)
        self._audit_log('WHITELIST_ADD', ip, 0, 'manual')

    def remove_from_whitelist(self, ip: str) -> None:
        """Remove IP from whitelist"""
        if not self._validate_ip(ip):
            return
        with self._lock:
            self.whitelist.discard(ip)
        self._audit_log('WHITELIST_REMOVE', ip, 0, 'manual')

    def check_rate_limit(self, src_ip: str, dst_port: int) -> bool:
        """
        Check if connection should be rate limited.
        Returns True if allowed, False if should be blocked.
        """
        if src_ip in self.whitelist:
            return True

        if not self._validate_ip(src_ip):
            return False

        with self._rate_lock:
            now = time.time()

            # Lazy initialization to save memory
            if src_ip not in self.rate_limits:
                if len(self.rate_limits) >= self.max_ips_tracked:
                    # Too many IPs tracked, cleanup old ones
                    self._cleanup_rate_entries()
                if len(self.rate_limits) >= self.max_ips_tracked:
                    return True  # Allow if we can't track
                self.rate_limits[src_ip] = {}

            # Get or create port entry
            port_dict = self.rate_limits[src_ip]
            if dst_port not in port_dict:
                if self._rate_entries_count >= self.max_rate_entries:
                    self._cleanup_rate_entries()
                if self._rate_entries_count >= self.max_rate_entries:
                    return True
                port_dict[dst_port] = deque(maxlen=self.rate_threshold)
                self._rate_entries_count += 1

            entry = port_dict[dst_port]
            cutoff = now - self.rate_window

            # Remove old entries
            while entry and entry[0] < cutoff:
                entry.popleft()

            entry.append(now)
            self.last_activity[src_ip] = now

            if len(entry) >= self.rate_threshold:
                self._apply_action(src_ip, dst_port, 'throttle')
                return False
            return True

    def _cleanup_rate_entries(self) -> None:
        """Remove old rate limit entries to prevent memory exhaustion"""
        now = time.time()
        cutoff = now - (self.rate_window * 2)

        with self._rate_lock:
            # Remove IPs with no recent activity
            stale_ips = [
                ip for ip, last_time in self.last_activity.items()
                if last_time < cutoff
            ]

            for ip in stale_ips:
                if ip in self.rate_limits:
                    self._rate_entries_count -= len(self.rate_limits[ip])
                    del self.rate_limits[ip]
                self.last_activity.pop(ip, None)

    def is_blocked(self, ip: str, port: Optional[int] = None) -> bool:
        """Check if an IP/port combination is blocked"""
        if not self._validate_ip(ip):
            return False

        with self._lock:
            if ip in self.whitelist:
                return False

            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True
                else:
                    # Expired block, clean up
                    del self.blocked_ips[ip]

            if port is not None and ip in self.blocked_ports:
                return port in self.blocked_ports[ip]

            return False

    def on_alert(self, alert: Dict) -> None:
        """Handle security alert with graduated response"""
        if not self.auto_block:
            return

        src_ip = alert.get('src_ip', '')
        dst_port = alert.get('dst_port', 0)
        severity = alert.get('severity', 'LOW')

        if not src_ip or src_ip in self.whitelist:
            return

        if not self._validate_ip(src_ip):
            return

        with self._lock:
            # Calculate severity increment
            severity_increments = {
                'CRITICAL': 4,
                'HIGH': 3,
                'MEDIUM': 2,
                'LOW': 1
            }
            increment = severity_increments.get(severity, 1)

            self.action_levels[src_ip] += increment
            level = min(4, self.action_levels[src_ip])
            action = self.response_levels[level]

            # Track action history
            now = time.time()
            self.action_history[src_ip].append((now, action))
            self.last_activity[src_ip] = now

            # Clean old history entries
            cutoff = now - 3600
            self.action_history[src_ip] = [
                (t, a) for t, a in self.action_history[src_ip]
                if t > cutoff
            ]

        # Apply action outside lock to prevent deadlocks
        self._apply_action(src_ip, dst_port, action, alert)

    def on_exfiltration(self, data: Dict) -> None:
        """Immediate response to data exfiltration detection"""
        if not self.auto_block:
            return

        src_ip = data.get('src_ip', '')
        if not src_ip or src_ip in self.whitelist:
            return

        if not self._validate_ip(src_ip):
            return

        # Immediate temporary block for data exfiltration
        self.logger.critical(f"DATA EXFILTRATION DETECTED - Immediate block: {src_ip}")
        self._apply_action(src_ip, 0, 'block_ip_temp', data)

    def _apply_action(self, src_ip: str, dst_port: int, action: str, context: Optional[Dict] = None) -> None:
        """Apply graduated security action (non-blocking)"""
        if src_ip in self.whitelist:
            return

        if not self._validate_ip(src_ip):
            self.logger.warning(f"Invalid IP in _apply_action: {src_ip}")
            return

        if action == 'throttle':
            self.logger.info(f"Rate limiting applied to {src_ip}:{dst_port}")
            # Implement actual throttling via iptables hashlimit or tc
            self._executor.submit(self._apply_throttle_rule, src_ip, dst_port)

        elif action == 'block_port':
            self.logger.warning(f"Blocking port {dst_port} for {src_ip}")
            with self._lock:
                self.blocked_ports[src_ip].add(dst_port)
            self._executor.submit(self._block_port_impl, src_ip, dst_port)
            self.event_bus.publish('firewall.port_blocked', {
                'ip': src_ip,
                'port': dst_port,
                'reason': context.get('attack_type', 'unknown') if context else 'unknown'
            })

        elif action == 'block_ip_temp':
            self.logger.warning(f"Temporary IP block: {src_ip} (30 minutes)")
            self._executor.submit(self.block_ip, src_ip, 1800)
            self.event_bus.publish('firewall.blocked', {
                'ip': src_ip,
                'duration': 1800,
                'permanent': False,
                'reason': context.get('attack_type', 'unknown') if context else 'unknown'
            })

        elif action == 'block_ip_perm':
            self.logger.warning(f"Permanent IP block: {src_ip} (24 hours)")
            self._executor.submit(self.block_ip, src_ip, 86400)
            self.event_bus.publish('firewall.blocked', {
                'ip': src_ip,
                'duration': 86400,
                'permanent': True,
                'reason': context.get('attack_type', 'unknown') if context else 'unknown'
            })

    def _apply_throttle_rule(self, src_ip: str, dst_port: int) -> bool:
        """Apply rate limiting rule using iptables hashlimit"""
        if os.name == 'nt':
            # Windows rate limiting is more complex, use netsh with QoS policies
            return self._apply_windows_throttle(src_ip, dst_port)

        try:
            # Create hashlimit rule for this IP
            rule_name = f"SHARD_THROTTLE_{src_ip.replace('.', '_')}"
            # Remove existing rule if present
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', src_ip, '-p', 'tcp',
                 '--dport', str(dst_port), '-m', 'hashlimit',
                 '--hashlimit-name', rule_name, '-j', 'DROP'],
                capture_output=True, timeout=5
            )
            # Add new rate limiting rule (100 packets per minute)
            result = subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', src_ip, '-p', 'tcp',
                 '--dport', str(dst_port), '-m', 'hashlimit',
                 '--hashlimit-above', '100/min', '--hashlimit-burst', '10',
                 '--hashlimit-name', rule_name, '-j', 'DROP'],
                capture_output=True, timeout=5, check=False
            )
            if result.returncode == 0:
                self.logger.debug(f"Throttle rule applied for {src_ip}:{dst_port}")
                return True
            else:
                self.logger.error(f"Failed to apply throttle: {result.stderr.decode()}")
                return False
        except Exception as e:
            self.logger.error(f"Error applying throttle rule: {e}")
            return False

    def _apply_windows_throttle(self, src_ip: str, dst_port: int) -> bool:
        """Apply rate limiting for Windows (simplified)"""
        # Windows Firewall doesn't natively support rate limiting
        # Could use netsh advfirewall with custom logging and additional logic
        self.logger.debug(f"Windows throttle not fully implemented for {src_ip}:{dst_port}")
        return True

    def block_ip(self, ip: str, duration: int = 3600) -> bool:
        """
        Block an IP address with duplicate prevention.
        Uses atomic operation to prevent race conditions.
        """
        if not self._validate_ip(ip):
            self.logger.error(f"Invalid IP address: {ip}")
            return False

        with self._lock:
            # Check whitelist
            if ip in self.whitelist:
                self.logger.debug(f"IP {ip} is whitelisted, blocking cancelled")
                return False

            # Check if already blocked
            if ip in self.blocked_ips:
                existing_expiry = self.blocked_ips[ip]
                if time.time() < existing_expiry:
                    self.logger.debug(
                        f"IP {ip} already blocked until "
                        f"{datetime.fromtimestamp(existing_expiry)}"
                    )
                    return False

            # Check if block operation already in progress
            if ip in self.pending_blocks:
                self.logger.debug(f"Block operation already in progress for {ip}")
                return False

            # Mark as pending to prevent duplicate operations
            self.pending_blocks.add(ip)

        # Execute blocking outside of lock (async context)
        try:
            success = self._block_ip_impl(ip, duration)

            with self._lock:
                if success:
                    self.blocked_ips[ip] = time.time() + duration
                    self._audit_log('BLOCK', ip, duration, 'auto')
                # Always remove from pending
                self.pending_blocks.discard(ip)

            return success

        except Exception as e:
            self.logger.error(f"Error blocking IP {ip}: {e}")
            with self._lock:
                self.pending_blocks.discard(ip)
            return False

    def _block_ip_impl(self, ip: str, duration: int) -> bool:
        """Low-level IP blocking implementation"""
        try:
            if os.name == 'nt':
                return self._block_ip_windows(ip, duration)
            else:
                return self._block_ip_linux(ip, duration)
        except Exception as e:
            self.logger.error(f"Block implementation failed for {ip}: {e}")
            return False

    def _block_ip_windows(self, ip: str, duration: int) -> bool:
        """Block IP using Windows Firewall"""
        rule_name = f"SHARD_Block_{ip.replace('.', '_')}"

        # Validate rule name
        if not re.match(r'^[a-zA-Z0-9_]+$', rule_name):
            self.logger.error(f"Invalid rule name: {rule_name}")
            return False

        # Check if rule already exists
        check_result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],
            capture_output=True, text=True, timeout=5
        )

        if 'No rules match' not in check_result.stdout:
            self.logger.debug(f"Windows firewall rule already exists for {ip}")
            return True

        # Add blocking rule
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name={rule_name}', 'dir=in', f'remoteip={ip}',
             'action=block', 'enable=yes', 'profile=any'],
            capture_output=True, text=True, timeout=10, check=False
        )

        if result.returncode == 0:
            self.logger.info(f"IP {ip} blocked via Windows Firewall ({duration}s)")
            return True
        else:
            self.logger.error(f"Windows Firewall block failed: {result.stderr}")
            return False

    def _block_ip_linux(self, ip: str, duration: int) -> bool:
        """Block IP using iptables"""
        # Ensure chain exists
        if not self._chain_created:
            self.add_iptables_chain()

        # Check if rule already exists
        check_result = subprocess.run(
            ['iptables', '-C', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5
        )

        if check_result.returncode == 0:
            self.logger.debug(f"iptables rule already exists for {ip}")
            return True

        # Add blocking rule
        result = subprocess.run(
            ['iptables', '-A', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP',
             '-m', 'comment', '--comment', f'SHARD_block_{int(time.time())}'],
            capture_output=True, timeout=5, check=False
        )

        if result.returncode == 0:
            self.logger.info(f"IP {ip} blocked via iptables ({duration}s)")
            return True
        else:
            self.logger.error(f"iptables block failed: {result.stderr.decode()}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        if not self._validate_ip(ip):
            return False

        with self._lock:
            # Remove from internal tracking
            self._unblock_ip_internal(ip)

        # Remove firewall rules
        try:
            if os.name == 'nt':
                success = self._unblock_ip_windows(ip)
            else:
                success = self._unblock_ip_linux(ip)

            if success:
                self.logger.info(f"IP {ip} unblocked successfully")
                self._audit_log('UNBLOCK', ip, 0, 'manual')
            return success

        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip}: {e}")
            return False

    def _unblock_ip_windows(self, ip: str) -> bool:
        """Remove Windows Firewall rules for IP"""
        rule_name = f"SHARD_Block_{ip.replace('.', '_')}"
        if not re.match(r'^[a-zA-Z0-9_]+$', rule_name):
            return False

        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
            capture_output=True, timeout=10, check=False
        )
        return result.returncode == 0

    def _unblock_ip_linux(self, ip: str) -> bool:
        """Remove iptables rules for IP"""
        success = True
        while True:
            result = subprocess.run(
                ['iptables', '-D', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                break
        return success

    def block_port(self, ip: str, port: int) -> bool:
        """Block specific port for an IP"""
        if not self._validate_ip(ip) or not self._validate_port(port):
            self.logger.error(f"Invalid IP {ip} or port {port}")
            return False

        if ip in self.whitelist:
            return False

        with self._lock:
            self.blocked_ports[ip].add(port)

        return self._block_port_impl(ip, port)

    def _block_port_impl(self, ip: str, port: int) -> bool:
        """Low-level port blocking implementation"""
        try:
            if os.name == 'nt':
                return self._block_port_windows(ip, port)
            else:
                return self._block_port_linux(ip, port)
        except Exception as e:
            self.logger.error(f"Error blocking port {port} for {ip}: {e}")
            return False

    def _block_port_windows(self, ip: str, port: int) -> bool:
        """Block port using Windows Firewall"""
        rule_name = f"SHARD_Block_{ip.replace('.', '_')}_port_{port}"
        if not re.match(r'^[a-zA-Z0-9_]+$', rule_name.replace('_port_', '_')):
            return False

        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name={rule_name}', 'dir=in', f'remoteip={ip}',
             f'localport={port}', 'protocol=TCP', 'action=block'],
            capture_output=True, text=True, timeout=10, check=False
        )

        if result.returncode == 0:
            self.logger.info(f"Port {port} blocked for {ip} on Windows Firewall")
            return True
        return False

    def _block_port_linux(self, ip: str, port: int) -> bool:
        """Block port using iptables"""
        result = subprocess.run(
            ['iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp',
             '--dport', str(port), '-j', 'DROP',
             '-m', 'comment', '--comment', f'SHARD_port_block_{int(time.time())}'],
            capture_output=True, timeout=5, check=False
        )

        if result.returncode == 0:
            self.logger.info(f"Port {port} blocked for {ip} via iptables")
            return True
        return False

    def _validate_port(self, port: int) -> bool:
        """Validate port number"""
        return isinstance(port, int) and 0 < port < 65536

    def _validate_ip(self, ip: str) -> bool:
        """
        Strict IP address validation with command injection prevention.
        Only allows properly formatted IPv4 addresses.
        """
        if not ip or not isinstance(ip, str):
            return False

        # Strict format check: only digits and dots
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            return False

        # Validate octets
        try:
            octets = ip.split('.')
            return all(0 <= int(o) <= 255 for o in octets)
        except ValueError:
            return False

    def _audit_log(self, action: str, ip: str, duration: int, source: str = 'auto') -> None:
        """Write audit log entry"""
        try:
            audit_file = Path('logs/audit_firewall.log')
            timestamp = datetime.now().isoformat()
            log_entry = f"{timestamp} | {action} | {ip} | {duration}s | source={source}\n"

            with open(audit_file, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            self.logger.warning(f"Failed to write audit log: {e}")

    def add_iptables_chain(self) -> bool:
        """Create dedicated iptables chain for SHARD (idempotent)"""
        if os.name == 'nt' or self._chain_created:
            return True

        try:
            # Try to create chain (fails silently if exists)
            subprocess.run(
                ['iptables', '-N', 'SHARD_BLOCK'],
                capture_output=True, timeout=5, check=False
            )

            # Ensure jump rule exists
            check_jump = subprocess.run(
                ['iptables', '-C', 'INPUT', '-j', 'SHARD_BLOCK'],
                capture_output=True, timeout=5
            )

            if check_jump.returncode != 0:
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '1', '-j', 'SHARD_BLOCK'],
                    capture_output=True, timeout=5, check=False
                )

            self._chain_created = True
            self.logger.info("iptables SHARD_BLOCK chain initialized")
            return True

        except Exception as e:
            self.logger.error(f"Failed to create iptables chain: {e}")
            return False

    def _cleanup_loop(self) -> None:
        """Periodic cleanup of expired blocks and threat levels"""
        cleanup_interval = 60  # seconds

        while self.running:
            time.sleep(cleanup_interval)

            if not self.running:
                break

            now = time.time()

            try:
                # Clean expired blocks
                self._cleanup_expired_blocks(now)

                # Decrease threat levels for inactive IPs
                self._cleanup_threat_levels(now)

                # Clean rate limit entries
                self._cleanup_rate_entries()

            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")

    def _cleanup_expired_blocks(self, now: float) -> None:
        """Remove expired IP blocks"""
        expired_ips = []

        with self._lock:
            for ip, expiry in list(self.blocked_ips.items()):
                if expiry <= now:
                    expired_ips.append(ip)

        for ip in expired_ips:
            self.logger.debug(f"Removing expired block for {ip}")

            with self._lock:
                self._unblock_ip_internal(ip)

            # Remove firewall rules asynchronously
            self._executor.submit(self._remove_ip_rules, ip)

    def _remove_ip_rules(self, ip: str) -> None:
        """Remove firewall rules for an IP"""
        try:
            if os.name == 'nt':
                self._unblock_ip_windows(ip)
            else:
                self._unblock_ip_linux(ip)
        except Exception as e:
            self.logger.debug(f"Error removing rules for {ip}: {e}")

    def _cleanup_threat_levels(self, now: float) -> None:
        """Gradually decrease threat levels for inactive IPs"""
        ips_to_reset = []

        with self._lock:
            for ip in list(self.action_levels.keys()):
                history = self.action_history.get(ip, [])

                if history:
                    last_action_time = max(t for t, _ in history)
                    time_since_last = now - last_action_time

                    # Decrease level if inactive for 30 minutes
                    if time_since_last > 1800:
                        self.action_levels[ip] = max(0, self.action_levels[ip] - 1)

                        if self.action_levels[ip] == 0:
                            ips_to_reset.append(ip)
                else:
                    ips_to_reset.append(ip)

                # Clean old history entries
                cutoff = now - 7200  # 2 hours
                if ip in self.action_history:
                    self.action_history[ip] = [
                        (t, a) for t, a in self.action_history[ip]
                        if t > cutoff
                    ]

        # Reset IPs with zero threat level
        for ip in ips_to_reset:
            with self._lock:
                if ip in self.action_levels and self.action_levels[ip] == 0:
                    del self.action_levels[ip]
                    if ip in self.action_history:
                        del self.action_history[ip]
                    self.logger.debug(f"Threat level reset for {ip}")

    def _unblock_ip_internal(self, ip: str) -> None:
        """Internal method to remove all tracking for an IP"""
        self.blocked_ips.pop(ip, None)
        self.blocked_ports.pop(ip, None)
        self.action_levels.pop(ip, None)
        self.action_history.pop(ip, None)
        self.last_activity.pop(ip, None)

        with self._rate_lock:
            if ip in self.rate_limits:
                self._rate_entries_count -= len(self.rate_limits[ip])
                del self.rate_limits[ip]

    def flush_blocks(self) -> int:
        """Remove all firewall blocks and reset state"""
        count = 0

        try:
            # Remove firewall rules
            if os.name == 'nt':
                count = self._flush_windows_rules()
            else:
                count = self._flush_linux_rules()

            # Clear internal state
            with self._lock:
                self.blocked_ips.clear()
                self.blocked_ports.clear()
                self.action_levels.clear()
                self.action_history.clear()
                self.pending_blocks.clear()

            with self._rate_lock:
                self.rate_limits.clear()
                self._rate_entries_count = 0
                self.last_activity.clear()

            self.logger.info(f"Flushed {count} firewall rules")
            self._audit_log('FLUSH_ALL', '0.0.0.0', 0, 'manual')
            return count

        except Exception as e:
            self.logger.error(f"Error flushing blocks: {e}")
            return 0

    def _flush_windows_rules(self) -> int:
        """Remove all SHARD Windows Firewall rules"""
        count = 0

        try:
            # Get all rules
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                capture_output=True, text=True, timeout=30
            )

            # Parse and delete SHARD rules
            for line in result.stdout.split('\n'):
                if 'SHARD_Block_' in line or 'SHARD_THROTTLE_' in line:
                    # Extract rule name
                    parts = line.split(':')
                    if len(parts) >= 2:
                        rule_name = parts[1].strip()
                        # Delete the rule
                        subprocess.run(
                            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                             f'name={rule_name}'],
                            capture_output=True, timeout=5
                        )
                        count += 1

            return count

        except Exception as e:
            self.logger.error(f"Error flushing Windows rules: {e}")
            return count

    def _flush_linux_rules(self) -> int:
        """Flush all rules from SHARD_BLOCK chain"""
        try:
            result = subprocess.run(
                ['iptables', '-F', 'SHARD_BLOCK'],
                capture_output=True, timeout=10, check=False
            )

            if result.returncode == 0:
                # Count remaining rules (should be 0)
                count_result = subprocess.run(
                    ['iptables', '-L', 'SHARD_BLOCK', '-n'],
                    capture_output=True, text=True, timeout=5
                )
                # Count lines that look like rules (contain DROP/REJECT)
                rule_lines = [
                    line for line in count_result.stdout.split('\n')
                    if 'DROP' in line or 'REJECT' in line
                ]
                return len(rule_lines)

            return 0

        except Exception as e:
            self.logger.error(f"Error flushing Linux rules: {e}")
            return 0

    def get_status(self) -> Dict:
        """Get current firewall status"""
        with self._lock:
            status = {
                'auto_block': self.auto_block,
                'blocked_ips': len(self.blocked_ips),
                'blocked_ports': sum(len(ports) for ports in self.blocked_ports.values()),
                'tracked_threats': len(self.action_levels),
                'whitelist_size': len(self.whitelist),
                'pending_operations': len(self.pending_blocks),
                'active_threats': {
                    ip: level for ip, level in self.action_levels.items()
                    if level >= 3
                }
            }

        with self._rate_lock:
            status['tracked_ips'] = len(self.rate_limits)
            status['rate_entries'] = self._rate_entries_count

        return status
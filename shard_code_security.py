#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SHARD Code Security Module
Анализ безопасности кода в реальном времени (Security by Design)
Аналог Infera AI.SafeCode для SHARD

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import re
import ast
import json
import time
import threading
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml


# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

class VulnerabilitySeverity(Enum):
    """Уровни серьёзности уязвимостей"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(Enum):
    """Типы уязвимостей"""
    # Injection
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    CODE_INJECTION = "Code Injection"
    LDAP_INJECTION = "LDAP Injection"
    XML_INJECTION = "XML Injection"

    # XSS
    REFLECTED_XSS = "Reflected XSS"
    STORED_XSS = "Stored XSS"
    DOM_XSS = "DOM XSS"

    # Security Misconfiguration
    HARDCODED_SECRET = "Hardcoded Secret"
    HARDCODED_CREDENTIAL = "Hardcoded Credential"
    DEBUG_ENABLED = "Debug Mode Enabled"
    INSECURE_CONFIG = "Insecure Configuration"

    # Cryptographic Failures
    WEAK_CRYPTO = "Weak Cryptography"
    WEAK_HASH = "Weak Hash Algorithm"
    HARDCODED_KEY = "Hardcoded Encryption Key"
    INSUFFICIENT_ENTROPY = "Insufficient Entropy"

    # Access Control
    MISSING_AUTH = "Missing Authentication"
    BROKEN_ACCESS_CONTROL = "Broken Access Control"
    PRIVILEGE_ESCALATION = "Privilege Escalation"

    # File Operations
    PATH_TRAVERSAL = "Path Traversal"
    INSECURE_FILE_UPLOAD = "Insecure File Upload"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"

    # Network
    SSRF = "Server-Side Request Forgery"
    OPEN_REDIRECT = "Open Redirect"
    INSECURE_TLS = "Insecure TLS Configuration"

    # Other
    RACE_CONDITION = "Race Condition"
    INTEGER_OVERFLOW = "Integer Overflow"
    NULL_POINTER = "Null Pointer Dereference"


@dataclass
class CodeSecurityConfig:
    """Конфигурация анализатора кода"""

    # Языки для анализа
    enabled_languages: List[str] = field(default_factory=lambda: ['python', 'javascript', 'go', 'java', 'php', 'ruby'])

    # Правила
    enable_builtin_rules: bool = True
    custom_rules_path: str = "./data/code_security/custom_rules.yaml"

    # Сканирование
    max_file_size_mb: int = 10
    max_files_per_scan: int = 10000
    scan_timeout_seconds: int = 300

    # Интеграция
    watch_directories: List[str] = field(default_factory=list)
    auto_scan_on_commit: bool = True
    block_on_critical: bool = False

    # Отчёты
    reports_dir: str = "./data/code_security/reports/"
    save_findings: bool = True

    # Severity thresholds
    fail_on_severity: str = "CRITICAL"
    warn_on_severity: str = "HIGH"


# ============================================================
# БАЗА ЗНАНИЙ УЯЗВИМОСТЕЙ
# ============================================================

class VulnerabilityKnowledgeBase:
    """База знаний уязвимостей для разных языков"""

    def __init__(self):
        self.rules: Dict[str, List[Dict]] = {}
        self._init_builtin_rules()

    def _init_builtin_rules(self):
        """Инициализация встроенных правил"""

        # ===== PYTHON =====
        self.rules['python'] = [
            # Command Injection
            {
                'id': 'PY-CMD-001',
                'name': 'Command Injection via os.system',
                'pattern': r'os\.system\s*\(\s*[^\'"]*[\'"]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'Use of os.system() with user-controlled input can lead to command injection',
                'remediation': 'Use subprocess.run() with shell=False and argument list',
                'cwe': 'CWE-78'
            },
            {
                'id': 'PY-CMD-002',
                'name': 'Command Injection via subprocess with shell=True',
                'pattern': r'subprocess\.[a-zA-Z_]*\(\s*.*shell\s*=\s*True',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'subprocess with shell=True is vulnerable to command injection',
                'remediation': 'Set shell=False and pass arguments as list',
                'cwe': 'CWE-78'
            },
            {
                'id': 'PY-CMD-003',
                'name': 'Command Injection via os.popen',
                'pattern': r'os\.popen\s*\(',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'os.popen() executes shell commands',
                'remediation': 'Use subprocess module with proper argument handling',
                'cwe': 'CWE-78'
            },

            # Code Injection
            {
                'id': 'PY-CODE-001',
                'name': 'Code Injection via eval',
                'pattern': r'eval\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.CODE_INJECTION,
                'description': 'eval() executes arbitrary Python code',
                'remediation': 'Never use eval(). Use ast.literal_eval() or JSON parsing instead',
                'cwe': 'CWE-95'
            },
            {
                'id': 'PY-CODE-002',
                'name': 'Code Injection via exec',
                'pattern': r'exec\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.CODE_INJECTION,
                'description': 'exec() executes arbitrary Python code',
                'remediation': 'Never use exec() with user input',
                'cwe': 'CWE-95'
            },
            {
                'id': 'PY-CODE-003',
                'name': 'Dynamic Import',
                'pattern': r'__import__\s*\(',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.CODE_INJECTION,
                'description': '__import__() with user input can load arbitrary modules',
                'remediation': 'Use importlib.import_module() with whitelist',
                'cwe': 'CWE-95'
            },
            {
                'id': 'PY-CODE-004',
                'name': 'Unsafe Pickle Deserialization',
                'pattern': r'pickle\.(load|loads)\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.INSECURE_DESERIALIZATION,
                'description': 'pickle deserialization can execute arbitrary code',
                'remediation': 'Never unpickle untrusted data. Use JSON instead',
                'cwe': 'CWE-502'
            },
            {
                'id': 'PY-CODE-005',
                'name': 'Unsafe YAML Loading',
                'pattern': r'yaml\.load\s*\(\s*[^,)]*[^L]',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.INSECURE_DESERIALIZATION,
                'description': 'yaml.load() without SafeLoader can create arbitrary objects',
                'remediation': 'Use yaml.safe_load() instead',
                'cwe': 'CWE-502'
            },

            # SQL Injection
            {
                'id': 'PY-SQL-001',
                'name': 'SQL Injection via string formatting',
                'pattern': r'\.execute\s*\(\s*[^)]*%[^)]*\)',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'Using % formatting in SQL queries is vulnerable to injection',
                'remediation': 'Use parameterized queries with placeholders',
                'cwe': 'CWE-89'
            },
            {
                'id': 'PY-SQL-002',
                'name': 'SQL Injection via .format()',
                'pattern': r'\.execute\s*\(\s*[^)]*\.format\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'Using .format() in SQL queries is vulnerable to injection',
                'remediation': 'Use parameterized queries with placeholders',
                'cwe': 'CWE-89'
            },
            {
                'id': 'PY-SQL-003',
                'name': 'SQL Injection via f-string',
                'pattern': r'\.execute\s*\(\s*f[\'"]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'Using f-strings in SQL queries is vulnerable to injection',
                'remediation': 'Use parameterized queries with placeholders',
                'cwe': 'CWE-89'
            },
            {
                'id': 'PY-SQL-004',
                'name': 'SQL Injection via concatenation',
                'pattern': r'\.execute\s*\(\s*[^\'"]*\+\s*',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'String concatenation in SQL queries is vulnerable to injection',
                'remediation': 'Use parameterized queries with placeholders',
                'cwe': 'CWE-89'
            },

            # Hardcoded Secrets
            {
                'id': 'PY-SECRET-001',
                'name': 'Hardcoded Password',
                'pattern': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_CREDENTIAL,
                'description': 'Hardcoded password in source code',
                'remediation': 'Use environment variables or secrets manager',
                'cwe': 'CWE-798'
            },
            {
                'id': 'PY-SECRET-002',
                'name': 'Hardcoded API Key',
                'pattern': r'(?i)(api[_-]?key|apikey|token)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_SECRET,
                'description': 'Hardcoded API key in source code',
                'remediation': 'Use environment variables or secrets manager',
                'cwe': 'CWE-798'
            },
            {
                'id': 'PY-SECRET-003',
                'name': 'Hardcoded AWS Key',
                'pattern': r'(?i)(aws[_-]?(access|secret)|AKIA[A-Z0-9]{16})',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_SECRET,
                'description': 'AWS credentials in source code',
                'remediation': 'Use IAM roles or environment variables',
                'cwe': 'CWE-798'
            },
            {
                'id': 'PY-SECRET-004',
                'name': 'Hardcoded Private Key',
                'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_SECRET,
                'description': 'Private key in source code',
                'remediation': 'Store keys in secure key management system',
                'cwe': 'CWE-798'
            },

            # Path Traversal
            {
                'id': 'PY-PATH-001',
                'name': 'Path Traversal via user input',
                'pattern': r'open\s*\(\s*[^)]*\.\./',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.PATH_TRAVERSAL,
                'description': 'File path constructed with user input may allow directory traversal',
                'remediation': 'Use os.path.abspath() and validate paths',
                'cwe': 'CWE-22'
            },

            # SSRF
            {
                'id': 'PY-SSRF-001',
                'name': 'Server-Side Request Forgery',
                'pattern': r'(requests|urllib|httpx)\.(get|post|request)\s*\(\s*[^)]*format',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.SSRF,
                'description': 'URL constructed with user input may allow SSRF',
                'remediation': 'Validate and whitelist URLs, use URL parsing',
                'cwe': 'CWE-918'
            },

            # Weak Crypto
            {
                'id': 'PY-CRYPTO-001',
                'name': 'Weak Hash Algorithm (MD5)',
                'pattern': r'hashlib\.md5\s*\(',
                'severity': VulnerabilitySeverity.MEDIUM,
                'type': VulnerabilityType.WEAK_HASH,
                'description': 'MD5 is cryptographically broken',
                'remediation': 'Use SHA-256 or SHA-3',
                'cwe': 'CWE-328'
            },
            {
                'id': 'PY-CRYPTO-002',
                'name': 'Weak Hash Algorithm (SHA1)',
                'pattern': r'hashlib\.sha1\s*\(',
                'severity': VulnerabilitySeverity.MEDIUM,
                'type': VulnerabilityType.WEAK_HASH,
                'description': 'SHA-1 is considered weak',
                'remediation': 'Use SHA-256 or SHA-3',
                'cwe': 'CWE-328'
            },
            {
                'id': 'PY-CRYPTO-003',
                'name': 'Insecure Random',
                'pattern': r'random\.(random|randint|choice)\s*\(',
                'severity': VulnerabilitySeverity.MEDIUM,
                'type': VulnerabilityType.INSUFFICIENT_ENTROPY,
                'description': 'random module is not cryptographically secure',
                'remediation': 'Use secrets module for security-sensitive operations',
                'cwe': 'CWE-330'
            },
        ]

        # ===== JAVASCRIPT =====
        self.rules['javascript'] = [
            # XSS
            {
                'id': 'JS-XSS-001',
                'name': 'innerHTML XSS',
                'pattern': r'\.innerHTML\s*=',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.DOM_XSS,
                'description': 'innerHTML with user input can lead to XSS',
                'remediation': 'Use textContent or sanitize with DOMPurify',
                'cwe': 'CWE-79'
            },
            {
                'id': 'JS-XSS-002',
                'name': 'document.write XSS',
                'pattern': r'document\.write\s*\(',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.DOM_XSS,
                'description': 'document.write with user input can lead to XSS',
                'remediation': 'Avoid document.write, use DOM manipulation methods',
                'cwe': 'CWE-79'
            },
            {
                'id': 'JS-XSS-003',
                'name': 'eval XSS',
                'pattern': r'eval\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.CODE_INJECTION,
                'description': 'eval() executes arbitrary JavaScript',
                'remediation': 'Never use eval()',
                'cwe': 'CWE-95'
            },
            {
                'id': 'JS-XSS-004',
                'name': 'Function constructor',
                'pattern': r'new\s+Function\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.CODE_INJECTION,
                'description': 'Function constructor is similar to eval',
                'remediation': 'Avoid dynamic code execution',
                'cwe': 'CWE-95'
            },

            # Injection
            {
                'id': 'JS-INJ-001',
                'name': 'Command Injection in child_process',
                'pattern': r'(exec|execSync|spawn)\s*\(\s*[^)]*\+',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'String concatenation in child_process can lead to command injection',
                'remediation': 'Use execFile or spawn with argument array',
                'cwe': 'CWE-78'
            },

            # Hardcoded Secrets
            {
                'id': 'JS-SECRET-001',
                'name': 'Hardcoded API Key',
                'pattern': r'(?i)(api[_-]?key|apikey|token)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_SECRET,
                'description': 'Hardcoded API key',
                'remediation': 'Use environment variables',
                'cwe': 'CWE-798'
            },
            {
                'id': 'JS-SECRET-002',
                'name': 'Hardcoded Password',
                'pattern': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_CREDENTIAL,
                'description': 'Hardcoded password',
                'remediation': 'Use environment variables',
                'cwe': 'CWE-798'
            },

            # localStorage for sensitive data
            {
                'id': 'JS-STORAGE-001',
                'name': 'Sensitive data in localStorage',
                'pattern': r'localStorage\.setItem\s*\(\s*[\'"`](token|password|secret|key)',
                'severity': VulnerabilitySeverity.MEDIUM,
                'type': VulnerabilityType.INSECURE_CONFIG,
                'description': 'Storing sensitive data in localStorage is insecure',
                'remediation': 'Use HttpOnly cookies for sensitive data',
                'cwe': 'CWE-922'
            },
        ]

        # ===== GO =====
        self.rules['go'] = [
            # Command Injection
            {
                'id': 'GO-CMD-001',
                'name': 'Command Injection',
                'pattern': r'exec\.Command\s*\(\s*[^)]*\+',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'String concatenation in exec.Command can lead to command injection',
                'remediation': 'Pass arguments separately, not via shell',
                'cwe': 'CWE-78'
            },

            # SQL Injection
            {
                'id': 'GO-SQL-001',
                'name': 'SQL Injection via fmt.Sprintf',
                'pattern': r'fmt\.Sprintf\s*\(\s*["\'].*SELECT',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'Using fmt.Sprintf for SQL queries is vulnerable',
                'remediation': 'Use placeholders ($1, $2) with database/sql',
                'cwe': 'CWE-89'
            },

            # Hardcoded Secrets
            {
                'id': 'GO-SECRET-001',
                'name': 'Hardcoded Secret',
                'pattern': r'(?i)(password|secret|key|token)\s*:=\s*"[^"]+"',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_SECRET,
                'description': 'Hardcoded secret in source code',
                'remediation': 'Use environment variables or secret manager',
                'cwe': 'CWE-798'
            },

            # Unsafe operations
            {
                'id': 'GO-UNSAFE-001',
                'name': 'Unsafe pointer usage',
                'pattern': r'unsafe\.Pointer',
                'severity': VulnerabilitySeverity.MEDIUM,
                'type': VulnerabilityType.INSECURE_CONFIG,
                'description': 'Using unsafe package can lead to memory corruption',
                'remediation': 'Avoid unsafe package unless absolutely necessary',
                'cwe': 'CWE-119'
            },
        ]

        # ===== JAVA =====
        self.rules['java'] = [
            # Command Injection
            {
                'id': 'JAVA-CMD-001',
                'name': 'Command Injection in Runtime.exec',
                'pattern': r'Runtime\.getRuntime\(\)\.exec\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'Runtime.exec with user input can lead to command injection',
                'remediation': 'Use ProcessBuilder with argument list',
                'cwe': 'CWE-78'
            },

            # SQL Injection
            {
                'id': 'JAVA-SQL-001',
                'name': 'SQL Injection in Statement',
                'pattern': r'Statement\.execute(Query|Update)?\s*\(\s*[^)]*\+',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'String concatenation in SQL is vulnerable',
                'remediation': 'Use PreparedStatement',
                'cwe': 'CWE-89'
            },

            # Hardcoded Secrets
            {
                'id': 'JAVA-SECRET-001',
                'name': 'Hardcoded Password',
                'pattern': r'(?i)password\s*=\s*"[^"]+"',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_CREDENTIAL,
                'description': 'Hardcoded password',
                'remediation': 'Use environment variables or vault',
                'cwe': 'CWE-798'
            },

            # Deserialization
            {
                'id': 'JAVA-DESER-001',
                'name': 'Unsafe Deserialization',
                'pattern': r'ObjectInputStream\.readObject\s*\(',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.INSECURE_DESERIALIZATION,
                'description': 'Deserializing untrusted data can lead to RCE',
                'remediation': 'Validate and filter before deserialization',
                'cwe': 'CWE-502'
            },

            # XXE
            {
                'id': 'JAVA-XXE-001',
                'name': 'XXE Vulnerability',
                'pattern': r'DocumentBuilderFactory\.newInstance\s*\(\)(?!.*setExpandEntityReferences)',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.XML_INJECTION,
                'description': 'XML parser may be vulnerable to XXE',
                'remediation': 'Disable external entities: setExpandEntityReferences(false)',
                'cwe': 'CWE-611'
            },
        ]

        # ===== PHP =====
        self.rules['php'] = [
            # Command Injection
            {
                'id': 'PHP-CMD-001',
                'name': 'Command Injection',
                'pattern': r'(system|exec|shell_exec|passthru|popen)\s*\(',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'Executing system commands with user input',
                'remediation': 'Use escapeshellarg() and escapeshellcmd()',
                'cwe': 'CWE-78'
            },

            # SQL Injection
            {
                'id': 'PHP-SQL-001',
                'name': 'SQL Injection in mysql_query',
                'pattern': r'mysql_query\s*\(\s*[^)]*\$',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'Direct use of user input in SQL query',
                'remediation': 'Use PDO with prepared statements',
                'cwe': 'CWE-89'
            },

            # File Inclusion
            {
                'id': 'PHP-LFI-001',
                'name': 'Local File Inclusion',
                'pattern': r'(include|require|include_once|require_once)\s*\(\s*\$',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.PATH_TRAVERSAL,
                'description': 'File inclusion with user input',
                'remediation': 'Whitelist allowed files, never use user input directly',
                'cwe': 'CWE-98'
            },

            # Hardcoded Secrets
            {
                'id': 'PHP-SECRET-001',
                'name': 'Hardcoded Password',
                'pattern': r'\$password\s*=\s*[\'"][^\'"]+[\'"]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_CREDENTIAL,
                'description': 'Hardcoded password',
                'remediation': 'Use environment variables',
                'cwe': 'CWE-798'
            },

            # Unserialize
            {
                'id': 'PHP-DESER-001',
                'name': 'Unsafe Unserialize',
                'pattern': r'unserialize\s*\(\s*\$',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.INSECURE_DESERIALIZATION,
                'description': 'Unserializing user input can lead to object injection',
                'remediation': 'Never unserialize user input, use JSON instead',
                'cwe': 'CWE-502'
            },
        ]

        # ===== RUBY =====
        self.rules['ruby'] = [
            # Command Injection
            {
                'id': 'RUBY-CMD-001',
                'name': 'Command Injection',
                'pattern': r'(system|exec|`|%x)\s*[\(\{`]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.COMMAND_INJECTION,
                'description': 'Executing system commands with user input',
                'remediation': 'Use Shellwords.escape or system with argument list',
                'cwe': 'CWE-78'
            },

            # SQL Injection
            {
                'id': 'RUBY-SQL-001',
                'name': 'SQL Injection',
                'pattern': r'(where|find_by_sql|execute)\s*\(\s*["\']*#\{',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.SQL_INJECTION,
                'description': 'String interpolation in SQL query',
                'remediation': 'Use parameterized queries with ? placeholders',
                'cwe': 'CWE-89'
            },

            # Hardcoded Secrets
            {
                'id': 'RUBY-SECRET-001',
                'name': 'Hardcoded Secret',
                'pattern': r'(password|secret|key|token)\s*=\s*[\'"][^\'"]+[\'"]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.HARDCODED_SECRET,
                'description': 'Hardcoded secret',
                'remediation': 'Use Rails credentials or environment variables',
                'cwe': 'CWE-798'
            },

            # Mass Assignment
            {
                'id': 'RUBY-MASS-001',
                'name': 'Mass Assignment',
                'pattern': r'\.(new|create|update|attributes=)\s*\(\s*params',
                'severity': VulnerabilitySeverity.HIGH,
                'type': VulnerabilityType.BROKEN_ACCESS_CONTROL,
                'description': 'Mass assignment without strong parameters',
                'remediation': 'Use strong parameters: params.require(:model).permit(:fields)',
                'cwe': 'CWE-915'
            },

            # YAML Deserialization
            {
                'id': 'RUBY-YAML-001',
                'name': 'Unsafe YAML Load',
                'pattern': r'YAML\.load\s*\(\s*[^,)]*[^S]',
                'severity': VulnerabilitySeverity.CRITICAL,
                'type': VulnerabilityType.INSECURE_DESERIALIZATION,
                'description': 'YAML.load can deserialize arbitrary Ruby objects',
                'remediation': 'Use YAML.safe_load',
                'cwe': 'CWE-502'
            },
        ]

    def get_rules(self, language: str) -> List[Dict]:
        """Получить правила для языка"""
        return self.rules.get(language, [])

    def add_custom_rule(self, language: str, rule: Dict):
        """Добавить кастомное правило"""
        if language not in self.rules:
            self.rules[language] = []
        self.rules[language].append(rule)

    def load_custom_rules(self, path: str):
        """Загрузить кастомные правила из YAML"""
        try:
            with open(path, 'r') as f:
                custom_rules = yaml.safe_load(f)
                for language, rules in custom_rules.items():
                    if language not in self.rules:
                        self.rules[language] = []
                    self.rules[language].extend(rules)
        except Exception as e:
            print(f"Error loading custom rules: {e}")


# ============================================================
# АНАЛИЗАТОР КОДА
# ============================================================

class CodeSecurityAnalyzer:
    """
    Анализатор безопасности кода
    Поддерживает Python, JavaScript, Go, Java, PHP, Ruby
    """

    def __init__(self, config: CodeSecurityConfig = None):
        self.config = config or CodeSecurityConfig()
        self.knowledge_base = VulnerabilityKnowledgeBase()

        # Загрузка кастомных правил
        if self.config.custom_rules_path:
            self.knowledge_base.load_custom_rules(self.config.custom_rules_path)

        # Статистика
        self.stats = {
            'total_files_scanned': 0,
            'total_lines_scanned': 0,
            'total_vulnerabilities': 0,
            'vulnerabilities_by_severity': defaultdict(int),
            'vulnerabilities_by_type': defaultdict(int),
            'vulnerabilities_by_language': defaultdict(int),
            'scan_duration_ms': 0
        }

        # Кэш результатов
        self.scan_cache: Dict[str, Tuple[float, List[Dict]]] = {}
        self.cache_ttl = 300  # 5 минут

        self._lock = threading.RLock()

    def analyze_file(self, filepath: str, force_rescan: bool = False) -> List[Dict]:
        """
        Анализ одного файла на уязвимости

        Args:
            filepath: Путь к файлу
            force_rescan: Принудительное пересканирование

        Returns:
            Список найденных уязвимостей
        """
        filepath = str(filepath)

        # Проверка кэша
        if not force_rescan and filepath in self.scan_cache:
            cached_time, cached_result = self.scan_cache[filepath]
            if time.time() - cached_time < self.cache_ttl:
                return cached_result

        # Проверка размера файла
        try:
            file_size = os.path.getsize(filepath)
            if file_size > self.config.max_file_size_mb * 1024 * 1024:
                return []
        except:
            return []

        # Определение языка
        ext = Path(filepath).suffix.lower()
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.mjs': 'javascript',
            '.ts': 'javascript',
            '.go': 'go',
            '.java': 'java',
            '.php': 'php',
            '.rb': 'ruby'
        }
        language = lang_map.get(ext)

        if not language or language not in self.config.enabled_languages:
            return []

        # Чтение файла
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
                lines = code.split('\n')
        except Exception as e:
            return [{
                'file': filepath,
                'error': str(e)
            }]

        # Анализ
        findings = []

        with self._lock:
            self.stats['total_files_scanned'] += 1
            self.stats['total_lines_scanned'] += len(lines)

        rules = self.knowledge_base.get_rules(language)

        for rule in rules:
            try:
                matches = re.finditer(rule['pattern'], code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Определение номера строки
                    line_no = code[:match.start()].count('\n') + 1

                    # Контекст (2 строки до и после)
                    start_line = max(0, line_no - 3)
                    end_line = min(len(lines), line_no + 2)
                    context = '\n'.join(lines[start_line:end_line])

                    finding = {
                        'file': filepath,
                        'language': language,
                        'line': line_no,
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'].value,
                        'type': rule['type'].value,
                        'description': rule['description'],
                        'remediation': rule['remediation'],
                        'cwe': rule.get('cwe', 'N/A'),
                        'snippet': context[:300],
                        'matched_text': match.group(0)[:100]
                    }

                    findings.append(finding)

                    with self._lock:
                        self.stats['total_vulnerabilities'] += 1
                        self.stats['vulnerabilities_by_severity'][rule['severity'].value] += 1
                        self.stats['vulnerabilities_by_type'][rule['type'].value] += 1
                        self.stats['vulnerabilities_by_language'][language] += 1
            except Exception as e:
                continue

        # Дополнительный анализ для Python (AST)
        if language == 'python':
            ast_findings = self._analyze_python_ast(filepath, code)
            findings.extend(ast_findings)

        # Дополнительный анализ для JavaScript (package.json)
        if language == 'javascript' and filepath.endswith('package.json'):
            dep_findings = self._analyze_package_json(filepath, code)
            findings.extend(dep_findings)

        # Сохранение в кэш
        with self._lock:
            self.scan_cache[filepath] = (time.time(), findings)
            if len(self.scan_cache) > 1000:
                # Очистка старых записей
                now = time.time()
                self.scan_cache = {k: v for k, v in self.scan_cache.items()
                                   if now - v[0] < self.cache_ttl}

        return findings

    def _analyze_python_ast(self, filepath: str, code: str) -> List[Dict]:
        """AST-анализ Python кода"""
        findings = []

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                # Проверка на использование eval/exec
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec']:
                            findings.append({
                                'file': filepath,
                                'language': 'python',
                                'line': node.lineno,
                                'rule_id': 'PY-AST-001',
                                'rule_name': f'Use of {node.func.id}()',
                                'severity': VulnerabilitySeverity.CRITICAL.value,
                                'type': VulnerabilityType.CODE_INJECTION.value,
                                'description': f'{node.func.id}() can execute arbitrary code',
                                'remediation': f'Never use {node.func.id}() with untrusted input',
                                'cwe': 'CWE-95',
                                'snippet': ast.unparse(node)[:200]
                            })

                    # Проверка на os.system
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'system' and hasattr(node.func.value, 'id') and node.func.value.id == 'os':
                            findings.append({
                                'file': filepath,
                                'language': 'python',
                                'line': node.lineno,
                                'rule_id': 'PY-AST-002',
                                'rule_name': 'Use of os.system()',
                                'severity': VulnerabilitySeverity.CRITICAL.value,
                                'type': VulnerabilityType.COMMAND_INJECTION.value,
                                'description': 'os.system() executes shell commands',
                                'remediation': 'Use subprocess.run() with shell=False',
                                'cwe': 'CWE-78',
                                'snippet': ast.unparse(node)[:200]
                            })

                # Проверка на hardcoded secrets в присваиваниях
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id.lower()
                            if any(secret in var_name for secret in
                                   ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key']):
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    if len(node.value.value) > 3:
                                        findings.append({
                                            'file': filepath,
                                            'language': 'python',
                                            'line': node.lineno,
                                            'rule_id': 'PY-AST-003',
                                            'rule_name': f'Hardcoded {var_name}',
                                            'severity': VulnerabilitySeverity.CRITICAL.value,
                                            'type': VulnerabilityType.HARDCODED_SECRET.value,
                                            'description': f'Hardcoded {var_name} in source code',
                                            'remediation': 'Use environment variables',
                                            'cwe': 'CWE-798',
                                            'snippet': f'{var_name} = "***REDACTED***"'
                                        })
        except SyntaxError:
            pass
        except Exception:
            pass

        return findings

    def _analyze_package_json(self, filepath: str, code: str) -> List[Dict]:
        """Анализ package.json на уязвимые зависимости"""
        findings = []

        try:
            data = json.loads(code)
            dependencies = {}
            dependencies.update(data.get('dependencies', {}))
            dependencies.update(data.get('devDependencies', {}))

            # Проверка известных уязвимых версий (упрощённо)
            vulnerable_packages = {
                'lodash': {'<4.17.21': 'Prototype Pollution'},
                'axios': {'<0.21.2': 'SSRF'},
                'express': {'<4.17.3': 'Open Redirect'},
                'moment': {'<2.29.2': 'Path Traversal'},
            }

            for pkg, version in dependencies.items():
                if pkg in vulnerable_packages:
                    clean_version = version.replace('^', '').replace('~', '')
                    for ver_range, vuln_type in vulnerable_packages[pkg].items():
                        findings.append({
                            'file': filepath,
                            'language': 'javascript',
                            'line': 0,
                            'rule_id': 'JS-DEP-001',
                            'rule_name': f'Vulnerable dependency: {pkg}',
                            'severity': VulnerabilitySeverity.HIGH.value,
                            'type': VulnerabilityType.INSECURE_CONFIG.value,
                            'description': f'{pkg} version {version} may have {vuln_type}',
                            'remediation': f'Update {pkg} to latest version',
                            'cwe': 'CWE-1104',
                            'snippet': f'"{pkg}": "{version}"'
                        })
        except:
            pass

        return findings

    def analyze_directory(self, directory: str, recursive: bool = True,
                          exclude_dirs: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Анализ директории

        Returns:
            Словарь {filepath: findings}
        """
        exclude_dirs = exclude_dirs or ['.git', '__pycache__', 'node_modules', 'venv', '.venv', 'dist', 'build']
        results = {}

        path = Path(directory)
        if not path.exists():
            return results

        # Сбор файлов
        files = []
        if recursive:
            for ext in ['.py', '.js', '.mjs', '.ts', '.go', '.java', '.php', '.rb']:
                for filepath in path.rglob(f'*{ext}'):
                    # Проверка исключений
                    if not any(excl in str(filepath) for excl in exclude_dirs):
                        files.append(filepath)
        else:
            for ext in ['.py', '.js', '.mjs', '.ts', '.go', '.java', '.php', '.rb']:
                for filepath in path.glob(f'*{ext}'):
                    files.append(filepath)

        # Ограничение количества файлов
        if len(files) > self.config.max_files_per_scan:
            files = files[:self.config.max_files_per_scan]

        # Параллельное сканирование
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self.analyze_file, str(f)): str(f) for f in files}

            for future in as_completed(futures):
                filepath = futures[future]
                try:
                    findings = future.result(timeout=30)
                    if findings:
                        results[filepath] = findings
                except Exception as e:
                    results[filepath] = [{'error': str(e)}]

        return results

    def analyze_on_commit(self, changed_files: List[str]) -> Dict[str, List[Dict]]:
        """
        Анализ изменённых файлов при коммите

        Returns:
            Словарь с находками и блокировкой критических уязвимостей
        """
        results = {}
        critical_found = False

        for filepath in changed_files:
            findings = self.analyze_file(filepath, force_rescan=True)
            if findings:
                results[filepath] = findings

                # Проверка на критические уязвимости
                for finding in findings:
                    if finding.get('severity') == VulnerabilitySeverity.CRITICAL.value:
                        critical_found = True

        return {
            'findings': results,
            'block_commit': critical_found and self.config.block_on_critical,
            'critical_found': critical_found
        }

    def generate_report(self, findings: Dict[str, List[Dict]], format: str = 'json') -> str:
        """Генерация отчёта"""
        report_data = {
            'timestamp': time.time(),
            'summary': {
                'total_files': len(findings),
                'total_findings': sum(len(f) for f in findings.values()),
                'by_severity': dict(self.stats['vulnerabilities_by_severity']),
                'by_type': dict(self.stats['vulnerabilities_by_type']),
                'by_language': dict(self.stats['vulnerabilities_by_language'])
            },
            'findings': findings,
            'stats': self.stats
        }

        if format == 'json':
            return json.dumps(report_data, indent=2)
        elif format == 'sarif':
            return self._to_sarif(report_data)
        else:
            return self._to_text(report_data)

    def _to_sarif(self, report_data: Dict) -> str:
        """Конвертация в SARIF формат"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SHARD Code Security",
                        "version": "5.0.0",
                        "informationUri": "https://shard.siem/",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        rule_ids = set()
        for filepath, findings in report_data['findings'].items():
            for finding in findings:
                rule_ids.add(finding.get('rule_id', 'unknown'))
                sarif['runs'][0]['results'].append({
                    "ruleId": finding.get('rule_id', 'unknown'),
                    "level": finding.get('severity', 'INFO').lower(),
                    "message": {
                        "text": finding.get('description', '')
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": filepath
                            },
                            "region": {
                                "startLine": finding.get('line', 1)
                            }
                        }
                    }]
                })

        for rule_id in rule_ids:
            sarif['runs'][0]['tool']['driver']['rules'].append({
                "id": rule_id,
                "name": rule_id
            })

        return json.dumps(sarif, indent=2)

    def _to_text(self, report_data: Dict) -> str:
        """Текстовый отчёт"""
        lines = []
        lines.append("=" * 80)
        lines.append("SHARD CODE SECURITY REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total files: {report_data['summary']['total_files']}")
        lines.append(f"Total findings: {report_data['summary']['total_findings']}")
        lines.append("")
        lines.append("BY SEVERITY:")
        for severity, count in report_data['summary']['by_severity'].items():
            lines.append(f"  {severity}: {count}")
        lines.append("")
        lines.append("-" * 80)

        for filepath, findings in report_data['findings'].items():
            lines.append(f"\n📁 {filepath}")
            for f in findings:
                lines.append(
                    f"  [{f.get('severity', 'INFO')}] Line {f.get('line', '?')}: {f.get('rule_name', 'Unknown')}")
                lines.append(f"      → {f.get('description', '')}")
                lines.append(f"      → Fix: {f.get('remediation', 'N/A')}")

        lines.append("\n" + "=" * 80)
        return '\n'.join(lines)

    def save_report(self, findings: Dict[str, List[Dict]], filename: str = None):
        """Сохранение отчёта"""
        if not filename:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"code_security_report_{timestamp}.json"

        report_path = Path(self.config.reports_dir) / filename
        report_path.parent.mkdir(parents=True, exist_ok=True)

        report = self.generate_report(findings, 'json')
        with open(report_path, 'w') as f:
            f.write(report)

        return str(report_path)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return {
                **self.stats,
                'cache_size': len(self.scan_cache),
                'vulnerabilities_by_severity': dict(self.stats['vulnerabilities_by_severity']),
                'vulnerabilities_by_type': dict(self.stats['vulnerabilities_by_type']),
                'vulnerabilities_by_language': dict(self.stats['vulnerabilities_by_language'])
            }

    def reset_stats(self):
        """Сброс статистики"""
        with self._lock:
            self.stats = {
                'total_files_scanned': 0,
                'total_lines_scanned': 0,
                'total_vulnerabilities': 0,
                'vulnerabilities_by_severity': defaultdict(int),
                'vulnerabilities_by_type': defaultdict(int),
                'vulnerabilities_by_language': defaultdict(int),
                'scan_duration_ms': 0
            }
            self.scan_cache.clear()


# ============================================================
# ИНТЕГРАЦИЯ С SHARD
# ============================================================

class ShardCodeSecurityIntegration:
    """Интеграция анализатора кода в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = CodeSecurityConfig()
        self.analyzer = CodeSecurityAnalyzer(self.config)
        self.event_bus = None
        self.logger = None
        self.watcher_threads: List[threading.Thread] = []
        self._running = False

    def setup(self, event_bus, logger):
        """Настройка интеграции"""
        self.event_bus = event_bus
        self.logger = logger

        if event_bus:
            event_bus.subscribe('code.scan.file', self.on_scan_file)
            event_bus.subscribe('code.scan.directory', self.on_scan_directory)
            event_bus.subscribe('code.scan.commit', self.on_scan_commit)

    def start(self):
        """Запуск интеграции"""
        self._running = True

        # Запуск вотчеров для директорий
        for directory in self.config.watch_directories:
            thread = threading.Thread(target=self._watch_directory, args=(directory,), daemon=True)
            thread.start()
            self.watcher_threads.append(thread)

        if self.logger:
            self.logger.info(f"🚀 Code Security запущен (следит за {len(self.config.watch_directories)} директориями)")

    def stop(self):
        """Остановка интеграции"""
        self._running = False

    def _watch_directory(self, directory: str):
        """Отслеживание изменений в директории"""
        import time
        from pathlib import Path

        path = Path(directory)
        if not path.exists():
            return

        last_scan = time.time()

        while self._running:
            time.sleep(60)  # Проверка каждую минуту

            try:
                # Поиск изменённых файлов
                changed_files = []
                for ext in ['.py', '.js', '.go', '.java', '.php', '.rb']:
                    for filepath in path.rglob(f'*{ext}'):
                        if filepath.stat().st_mtime > last_scan:
                            changed_files.append(str(filepath))

                if changed_files:
                    if self.logger:
                        self.logger.info(f"Обнаружено {len(changed_files)} изменённых файлов")

                    for filepath in changed_files[:10]:  # Ограничение
                        findings = self.analyzer.analyze_file(filepath, force_rescan=True)
                        if findings:
                            self._publish_findings(filepath, findings)

                last_scan = time.time()
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Ошибка вотчера: {e}")

    def _publish_findings(self, filepath: str, findings: List[Dict]):
        """Публикация находок как алертов"""
        critical_findings = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']]

        for finding in critical_findings:
            if self.event_bus:
                self.event_bus.publish('alert.detected', {
                    'attack_type': 'Code Vulnerability',
                    'severity': finding['severity'],
                    'score': 0.9 if finding['severity'] == 'CRITICAL' else 0.7,
                    'confidence': 0.95,
                    'explanation': finding['description'],
                    'details': finding
                })

        if self.logger and critical_findings:
            self.logger.warning(f"🔴 Найдено {len(critical_findings)} уязвимостей в {filepath}")

    def on_scan_file(self, data: Dict):
        """Обработка события сканирования файла"""
        filepath = data.get('filepath', '')
        findings = self.analyzer.analyze_file(filepath, force_rescan=True)

        if self.event_bus:
            self.event_bus.publish('code.scan.completed', {
                'filepath': filepath,
                'findings': findings,
                'request_id': data.get('request_id')
            })

        self._publish_findings(filepath, findings)

    def on_scan_directory(self, data: Dict):
        """Обработка события сканирования директории"""
        directory = data.get('directory', '')
        recursive = data.get('recursive', True)

        findings = self.analyzer.analyze_directory(directory, recursive)

        # Сохранение отчёта
        report_path = self.analyzer.save_report(findings)

        # Подсчёт критических
        critical_count = sum(
            1 for file_findings in findings.values()
            for f in file_findings if f.get('severity') == 'CRITICAL'
        )

        if self.event_bus:
            self.event_bus.publish('code.scan.completed', {
                'directory': directory,
                'total_files': len(findings),
                'total_findings': sum(len(f) for f in findings.values()),
                'critical_found': critical_count,
                'report_path': report_path,
                'request_id': data.get('request_id')
            })

        if self.logger:
            self.logger.info(f"📊 Сканирование {directory}: {len(findings)} файлов, {critical_count} критических")

    def on_scan_commit(self, data: Dict):
        """Обработка события pre-commit сканирования"""
        changed_files = data.get('files', [])
        result = self.analyzer.analyze_on_commit(changed_files)

        if self.event_bus:
            self.event_bus.publish('code.scan.commit_result', {
                **result,
                'request_id': data.get('request_id')
            })

        if result['block_commit']:
            if self.logger:
                self.logger.critical("🚫 Коммит заблокирован из-за критических уязвимостей!")

    def scan_repository(self, repo_path: str) -> Dict:
        """Полное сканирование репозитория"""
        findings = self.analyzer.analyze_directory(repo_path, recursive=True)
        report_path = self.analyzer.save_report(findings)

        return {
            'findings': findings,
            'report_path': report_path,
            'stats': self.analyzer.get_stats()
        }

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return self.analyzer.get_stats()


# ============================================================
# ТЕСТИРОВАНИЕ
# ============================================================

def test_code_security():
    """Тестирование анализатора кода"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ CODE SECURITY ANALYZER")
    print("=" * 60)

    analyzer = CodeSecurityAnalyzer()

    # Тест 1: Анализ Python кода с уязвимостями
    print("\n📝 Тест 1: Анализ Python кода")
    test_code = '''
import os
import pickle
import hashlib

def vulnerable_function(user_input):
    # Command Injection
    os.system("ls " + user_input)

    # SQL Injection
    query = "SELECT * FROM users WHERE id = '%s'" % user_input

    # Code Injection
    result = eval(user_input)

    # Hardcoded secret
    password = "super_secret_123"
    api_key = "sk-1234567890abcdef"

    # Unsafe deserialization
    data = pickle.loads(user_input)

    # Weak crypto
    hash = hashlib.md5(user_input).hexdigest()

    return result
'''

    # Сохраняем тестовый файл
    test_file = "/tmp/test_vulnerable.py"
    with open(test_file, 'w') as f:
        f.write(test_code)

    findings = analyzer.analyze_file(test_file)
    print(f"   Найдено уязвимостей: {len(findings)}")
    for f in findings:
        print(f"      [{f['severity']}] Line {f['line']}: {f['rule_name']}")

    # Тест 2: Анализ JavaScript кода
    print("\n📝 Тест 2: Анализ JavaScript кода")
    test_js = '''
const userInput = req.query.input;
// XSS
document.getElementById('output').innerHTML = userInput;
// Command Injection
const { exec } = require('child_process');
exec('ls ' + userInput);
// Hardcoded secret
const apiKey = "sk-abcdef123456";
// Eval
eval(userInput);
'''

    test_js_file = "/tmp/test_vulnerable.js"
    with open(test_js_file, 'w') as f:
        f.write(test_js)

    findings = analyzer.analyze_file(test_js_file)
    print(f"   Найдено уязвимостей: {len(findings)}")
    for f in findings:
        print(f"      [{f['severity']}] Line {f['line']}: {f['rule_name']}")

    # Тест 3: Генерация отчёта
    print("\n📝 Тест 3: Генерация отчёта")
    results = {
        test_file: analyzer.analyze_file(test_file),
        test_js_file: analyzer.analyze_file(test_js_file)
    }
    report = analyzer.generate_report(results, 'json')
    print(f"   Отчёт сгенерирован, размер: {len(report)} байт")

    # Статистика
    print("\n📊 Статистика:")
    stats = analyzer.get_stats()
    for key, value in stats.items():
        if not isinstance(value, dict):
            print(f"   {key}: {value}")

    # Очистка
    os.unlink(test_file)
    os.unlink(test_js_file)

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_code_security()
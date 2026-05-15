#!/usr/bin/env python3
"""SHARD LDAPContextProvider Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import os, time, threading, re, queue
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

class LDAPContextProvider(BaseModule):
    """Получение контекста из Active Directory / LDAP (исправлен - реальное шифрование пароля)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("LDAP", config, event_bus, logger)

        self.server = config.get('ldap.server') or os.environ.get('LDAP_SERVER', '')
        self.domain = config.get('ldap.domain') or os.environ.get('LDAP_DOMAIN', '')
        self.base_dn = config.get('ldap.base_dn') or os.environ.get('LDAP_BASE_DN', '')
        self.bind_user = config.get('ldap.bind_user') or os.environ.get('LDAP_BIND_USER', '')

        # ========== РЕАЛЬНОЕ ШИФРОВАНИЕ ПАРОЛЯ ==========
        self._cipher = None
        self._bind_password_encrypted = None

        raw_password = config.get('ldap.bind_password') or os.environ.get('LDAP_BIND_PASSWORD', '')
        if raw_password:
            try:
                from cryptography.fernet import Fernet
                self._cipher = Fernet(self._get_or_create_key())
                self._bind_password_encrypted = self._cipher.encrypt(raw_password.encode())
                self.logger.info("LDAP пароль зашифрован с Fernet")
            except ImportError:
                # Fallback - base64 (только для совместимости, небезопасно!)
                import base64
                self._bind_password_encrypted = base64.b64encode(raw_password.encode()).decode()
                self.logger.warning("cryptography не установлен, пароль в base64 (НЕБЕЗОПАСНО!)")
            finally:
                # Очищаем raw_password из памяти
                raw_password = None

        # Удаляем пароль из переменных окружения если он там был
        if 'LDAP_BIND_PASSWORD' in os.environ:
            del os.environ['LDAP_BIND_PASSWORD']
        # ===============================================

        self.use_ssl = config.get('ldap.use_ssl', True)
        self.port = config.get('ldap.port', 636 if self.use_ssl else 389)

        self.user_cache: Dict[str, Dict] = {}
        self.group_cache: Dict[str, Dict] = {}
        self.computer_cache: Dict[str, Dict] = {}
        self.cache_ttl = 3600
        self.ldap_connection = None
        self.ldap_available = False

        # Привилегированные группы
        self.privileged_groups = {
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Administrators', 'Backup Operators', 'Account Operators',
            'Server Operators', 'Print Operators', 'Remote Desktop Users',
            'DNS Admins', 'DHCP Administrators', 'Hyper-V Administrators'
        }

        # SID известных групп
        self.privileged_sids = {
            'S-1-5-21domain-512': 'Domain Admins',
            'S-1-5-21domain-519': 'Enterprise Admins',
            'S-1-5-21domain-518': 'Schema Admins',
            'S-1-5-32-544': 'Administrators',
            'S-1-5-32-551': 'Backup Operators',
            'S-1-5-32-548': 'Account Operators',
            'S-1-5-32-549': 'Server Operators',
            'S-1-5-32-550': 'Print Operators',
            'S-1-5-32-555': 'Remote Desktop Users'
        }

        self._lock = threading.RLock()
        self._connection_lock = threading.RLock()

        self.event_bus.subscribe('auth.login', self.on_login)
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('ldap.query.request', self.on_query_request)

    def _get_or_create_key(self) -> bytes:
        """Получить или создать ключ шифрования"""
        key_path = Path('data/ldap_key.key')
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            with open(key_path, 'rb') as f:
                return f.read()
        else:
            from cryptography.fernet import Fernet
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
            # Устанавливаем права только для владельца
            os.chmod(key_path, 0o600)
            return key

    def _get_bind_password(self) -> str:
        """Получить пароль (с расшифровкой)"""
        if not self._bind_password_encrypted:
            return ""
        try:
            if self._cipher:
                # Fernet шифрование
                return self._cipher.decrypt(self._bind_password_encrypted).decode()
            else:
                # Fallback base64
                import base64
                return base64.b64decode(self._bind_password_encrypted).decode()
        except Exception as e:
            self.logger.error(f"Ошибка расшифровки пароля: {e}")
            return ""

    def _sanitize_ldap_string(self, value: str, max_length: int = 200) -> str:
        """Санирование строк из LDAP"""
        if not value:
            return ""
        safe = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(value))
        return safe[:max_length]

    def start(self) -> None:
        self.running = True

        if self.server and self.bind_user:
            self.ldap_available = self._test_ldap_connection()
            if self.ldap_available:
                self.logger.info(f"LDAP провайдер запущен (сервер: {self.server}, домен: {self.domain})")
                threading.Thread(target=self._cache_refresh_loop, daemon=True).start()
            else:
                self.logger.warning("LDAP недоступен, используется режим ограниченной функциональности")
        else:
            self.logger.info("LDAP не настроен, используется базовый режим")

    def stop(self) -> None:
        self.running = False
        self._close_ldap_connection()

    def _get_ldap_connection(self):
        """Получение LDAP соединения (с безопасной работой с паролем)"""
        with self._connection_lock:
            if self.ldap_connection is not None:
                try:
                    self.ldap_connection.whoami_s()
                    return self.ldap_connection
                except:
                    self._close_ldap_connection()

            try:
                import ldap3
                from ldap3 import Server, Connection, ALL, NTLM

                if self.use_ssl:
                    server = Server(self.server, port=self.port, use_ssl=True, get_info=ALL)
                else:
                    server = Server(self.server, port=self.port, get_info=ALL)

                password = self._get_bind_password()

                try:
                    if '\\' in self.bind_user:
                        domain, username = self.bind_user.split('\\')
                        conn = Connection(
                            server,
                            user=f"{domain}\\{username}",
                            password=password,
                            authentication=NTLM,
                            auto_bind=True
                        )
                    else:
                        conn = Connection(
                            server,
                            user=self.bind_user,
                            password=password,
                            auto_bind=True
                        )

                    self.ldap_connection = conn
                    return conn
                finally:
                    # Стираем пароль из памяти
                    password = '\x00' * len(password)
                    del password

            except ImportError:
                self.logger.warning("ldap3 не установлен. Установите: pip install ldap3")
                return None
            except Exception as e:
                self.logger.error(f"Ошибка LDAP подключения: {type(e).__name__}")
                return None

    def _close_ldap_connection(self) -> None:
        """Закрытие LDAP соединения"""
        with self._connection_lock:
            if self.ldap_connection:
                try:
                    self.ldap_connection.unbind()
                except:
                    pass
                self.ldap_connection = None

    def _test_ldap_connection(self) -> bool:
        """Тестирование LDAP соединения"""
        conn = self._get_ldap_connection()
        if conn and conn.bound:
            self.logger.info("LDAP соединение успешно установлено")
            return True
        return False

    def _get_search_base(self) -> str:
        """Получение базы поиска"""
        if self.base_dn:
            return self.base_dn
        if self.domain:
            return ','.join([f"DC={part}" for part in self.domain.split('.')])
        return ""

    def _extract_cn_from_dn(self, dn: str) -> Optional[str]:
        """Извлечение CN из DN"""
        for part in dn.split(','):
            if part.strip().upper().startswith('CN='):
                return self._sanitize_ldap_string(part.strip()[3:], 100)
        return None

    def _sid_to_string(self, sid_bytes: bytes) -> str:
        """Преобразование SID из байт в строку"""
        try:
            if not sid_bytes:
                return ""
            revision = sid_bytes[0]
            sub_authority_count = sid_bytes[1]
            identifier_authority = int.from_bytes(sid_bytes[2:8], 'big')
            sid_string = f"S-{revision}-{identifier_authority}"
            for i in range(sub_authority_count):
                offset = 8 + i * 4
                sub_auth = int.from_bytes(sid_bytes[offset:offset + 4], 'little')
                sid_string += f"-{sub_auth}"
            return sid_string
        except:
            return ""

    def _filetime_to_datetime(self, filetime: int) -> Optional[str]:
        """Преобразование Windows FILETIME в datetime"""
        if filetime == 0 or filetime == 0x7FFFFFFFFFFFFFFF:
            return None
        try:
            epoch = datetime(1601, 1, 1)
            timestamp = filetime / 10000000
            dt = epoch + timedelta(seconds=timestamp)
            return dt.isoformat()
        except:
            return None

    def on_login(self, data: Dict) -> None:
        """Обогащение события входа LDAP контекстом"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')

        if username:
            context = self.get_user_context(username)
            data['ldap_context'] = context
            data['is_privileged'] = context.get('is_privileged', False)

            if src_ip:
                self.event_bus.publish('uba.bind_ip', {
                    'ip': src_ip,
                    'username': username
                })

    def on_alert(self, alert: Dict) -> None:
        """Добавление LDAP контекста к алерту"""
        src_ip = alert.get('src_ip', '')
        username = alert.get('username')

        if not username and src_ip:
            username = self._find_username_by_ip(src_ip)
            if username:
                alert['username'] = username

        if username:
            context = self.get_user_context(username)
            alert['ldap_context'] = context

            if context.get('is_privileged', False):
                alert['is_privileged_account'] = True
                current_severity = alert.get('severity', 'LOW')
                if current_severity == 'LOW':
                    alert['severity'] = 'MEDIUM'
                elif current_severity == 'MEDIUM':
                    alert['severity'] = 'HIGH'
                elif current_severity == 'HIGH':
                    alert['severity'] = 'CRITICAL'

                alert['score'] = min(1.0, alert.get('score', 0) + 0.3)

                if alert.get('explanation'):
                    alert['explanation'] += f' Атака на привилегированную учётную запись {username}!'
                else:
                    alert['explanation'] = f'Атака на привилегированную учётную запись {username}!'

    def on_query_request(self, data: Dict) -> None:
        """Обработка запроса к LDAP"""
        query_type = data.get('type', '')
        query_value = data.get('value', '')
        request_id = data.get('request_id', '')

        result = {}

        if query_type == 'user':
            result = self.get_user_context(query_value)
        elif query_type == 'group':
            result = {'members': self.get_group_members(query_value)}
        elif query_type == 'computer':
            result = self.get_computer_info(query_value)

        self.event_bus.publish('ldap.query.response', {
            'request_id': request_id,
            'result': result
        })

    def _find_username_by_ip(self, ip: str) -> Optional[str]:
        """Поиск username по IP в кэше"""
        with self._lock:
            for username, context in self.user_cache.items():
                if ip in context.get('recent_ips', []):
                    return username
        return None

    def get_user_context(self, username: str) -> Dict:
        """Получить контекст пользователя из LDAP"""
        with self._lock:
            if username in self.user_cache:
                cached = self.user_cache[username]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached.copy()

        context = self._fetch_user_context_ldap(username)

        if not context and self.ldap_available:
            for variant in self._get_username_variants(username):
                context = self._fetch_user_context_ldap(variant)
                if context:
                    break

        if not context:
            context = self._create_basic_context(username)

        with self._lock:
            context['timestamp'] = time.time()
            self.user_cache[username] = context.copy()

        return context

    def _get_username_variants(self, username: str) -> List[str]:
        """Получение вариантов username для поиска"""
        variants = [username]
        if '\\' in username:
            variants.append(username.split('\\')[1])
        if '@' in username:
            variants.append(username.split('@')[0])
        if self.domain:
            variants.append(f"{username}@{self.domain}")
            variants.append(f"{self.domain}\\{username}")
        return variants

    def _fetch_user_context_ldap(self, username: str) -> Optional[Dict]:
        """Реальный запрос к LDAP для получения контекста пользователя"""
        conn = self._get_ldap_connection()
        if not conn:
            return None

        try:
            search_filter = f"(|(sAMAccountName={username})(userPrincipalName={username}))"

            attributes = [
                'sAMAccountName', 'displayName', 'mail', 'department',
                'title', 'manager', 'memberOf', 'userAccountControl',
                'lastLogon', 'pwdLastSet', 'whenCreated', 'badPwdCount',
                'logonCount', 'homeDirectory', 'scriptPath', 'profilePath',
                'objectSid', 'primaryGroupID', 'distinguishedName'
            ]

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=attributes,
                size_limit=1
            )

            if not conn.entries:
                return None

            entry = conn.entries[0]

            context = {
                'username': self._sanitize_ldap_string(str(entry.sAMAccountName)) if hasattr(entry,
                                                                                             'sAMAccountName') else username,
                'display_name': self._sanitize_ldap_string(str(entry.displayName)) if hasattr(entry,
                                                                                              'displayName') else username,
                'email': self._sanitize_ldap_string(str(entry.mail), 100) if hasattr(entry, 'mail') else None,
                'department': self._sanitize_ldap_string(str(entry.department), 100) if hasattr(entry,
                                                                                                'department') else None,
                'title': self._sanitize_ldap_string(str(entry.title), 100) if hasattr(entry, 'title') else None,
                'manager': self._sanitize_ldap_string(str(entry.manager), 200) if hasattr(entry, 'manager') else None,
                'distinguished_name': self._sanitize_ldap_string(str(entry.distinguishedName), 300) if hasattr(entry,
                                                                                                               'distinguishedName') else None,
                'groups': [],
                'is_admin': False,
                'is_privileged': False,
                'enabled': True,
                'password_last_set': None,
                'last_logon': None,
                'bad_password_count': 0,
                'logon_count': 0,
                'recent_ips': [],
                'sid': None
            }

            if hasattr(entry, 'userAccountControl'):
                uac = int(entry.userAccountControl.value)
                context['enabled'] = not (uac & 0x0002)
                context['password_never_expires'] = bool(uac & 0x10000)
                context['is_locked'] = bool(uac & 0x0010)

            if hasattr(entry, 'memberOf'):
                for group_dn in entry.memberOf.values:
                    group_name = self._extract_cn_from_dn(group_dn)
                    if group_name:
                        context['groups'].append(group_name)
                        if group_name in self.privileged_groups:
                            context['is_privileged'] = True
                            context['is_admin'] = True

            if hasattr(entry, 'objectSid'):
                context['sid'] = self._sid_to_string(entry.objectSid.value)
                for priv_sid in self.privileged_sids:
                    if context['sid'] and priv_sid in context['sid']:
                        context['is_privileged'] = True

            if hasattr(entry, 'pwdLastSet') and entry.pwdLastSet.value:
                try:
                    context['password_last_set'] = self._filetime_to_datetime(int(entry.pwdLastSet.value))
                except:
                    pass

            if hasattr(entry, 'lastLogon') and entry.lastLogon.value:
                try:
                    context['last_logon'] = self._filetime_to_datetime(int(entry.lastLogon.value))
                except:
                    pass

            if hasattr(entry, 'badPwdCount'):
                context['bad_password_count'] = int(entry.badPwdCount.value)

            if hasattr(entry, 'logonCount'):
                context['logon_count'] = int(entry.logonCount.value)

            context['recent_ips'] = self._get_recent_logon_ips(username)

            return context

        except Exception as e:
            self.logger.error(f"Ошибка LDAP запроса для {username}: {type(e).__name__}")
            return None

    def _get_recent_logon_ips(self, username: str) -> List[str]:
        """Получение недавних IP из логов входа (исправлено - без утечки подписок)"""
        ips = []

        try:
            response_queue = queue.Queue()
            request_id = f"ldap_ips_{username}_{int(time.time())}_{threading.get_ident()}"

            received_response = threading.Event()
            response_data = {}

            def on_response(data):
                if data.get('request_id') == request_id:
                    response_data['ips'] = data.get('ips', [])
                    received_response.set()

            self.event_bus.subscribe('siem.ips.response', on_response)

            try:
                self.event_bus.publish('siem.ips.request', {
                    'request_id': request_id,
                    'username': username,
                    'hours': 24
                })

                if received_response.wait(timeout=3):
                    ips = response_data.get('ips', [])

            except Exception as e:
                self.logger.debug(f"Ошибка ожидания ответа SIEM: {e}")
            finally:
                self.event_bus.unsubscribe('siem.ips.response', on_response)

        except Exception as e:
            self.logger.debug(f"Ошибка получения IP для {username}: {e}")

        return ips

    def _create_basic_context(self, username: str) -> Dict:
        """Создание базового контекста когда LDAP недоступен"""
        context = {
            'username': username,
            'display_name': username,
            'groups': [],
            'is_admin': False,
            'is_privileged': False,
            'department': None,
            'title': None,
            'email': f"{username}@{self.domain}" if self.domain else None,
            'enabled': True,
            'password_last_set': None,
            'last_logon': None,
            'bad_password_count': 0,
            'logon_count': 0,
            'recent_ips': [],
            'source': 'basic'
        }

        username_lower = username.lower()
        privileged_keywords = ['admin', 'root', 'backup', 'service', 'sql', 'db', 'sys']

        for kw in privileged_keywords:
            if kw in username_lower:
                context['is_privileged'] = True
                context['groups'].append('Possible Privileged Account')
                break

        return context

    def is_privileged_account(self, username: str) -> bool:
        """Проверка, является ли учётная запись привилегированной"""
        ctx = self.get_user_context(username)
        return ctx.get('is_privileged', False)

    def get_group_members(self, group_name: str) -> List[str]:
        """Получить членов группы из LDAP"""
        with self._lock:
            if group_name in self.group_cache:
                cached = self.group_cache[group_name]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached.get('members', []).copy()

        members = self._fetch_group_members_ldap(group_name)

        if not members and self.ldap_available:
            group_dn = f"CN={group_name},CN=Users,{self._get_search_base()}"
            members = self._fetch_group_members_ldap(group_dn, use_filter=False)

        with self._lock:
            self.group_cache[group_name] = {
                'members': members.copy(),
                'timestamp': time.time()
            }

        return members

    def _fetch_group_members_ldap(self, group_identifier: str, use_filter: bool = True) -> List[str]:
        """Реальный запрос к LDAP для получения членов группы"""
        conn = self._get_ldap_connection()
        if not conn:
            return []

        try:
            if use_filter:
                search_filter = f"(&(objectClass=group)(|(cn={group_identifier})(sAMAccountName={group_identifier})))"
                search_base = self._get_search_base()
            else:
                search_filter = "(objectClass=*)"
                search_base = group_identifier

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['member'],
                size_limit=1
            )

            if not conn.entries:
                return []

            members = []
            if hasattr(conn.entries[0], 'member'):
                for member_dn in conn.entries[0].member.values:
                    username = self._extract_cn_from_dn(member_dn)
                    if username:
                        members.append(username)

            return members

        except Exception as e:
            self.logger.error(f"Ошибка получения членов группы {group_identifier}: {type(e).__name__}")
            return []

    def get_computer_info(self, computer_name: str) -> Dict:
        """Получить информацию о компьютере из AD"""
        with self._lock:
            if computer_name in self.computer_cache:
                cached = self.computer_cache[computer_name]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached.copy()

        info = self._fetch_computer_info_ldap(computer_name)

        if not info:
            info = {
                'name': computer_name,
                'enabled': True,
                'os': 'Unknown',
                'last_logon': None,
                'source': 'basic'
            }

        with self._lock:
            info['timestamp'] = time.time()
            self.computer_cache[computer_name] = info.copy()

        return info

    def _fetch_computer_info_ldap(self, computer_name: str) -> Optional[Dict]:
        """Запрос информации о компьютере из LDAP"""
        conn = self._get_ldap_connection()
        if not conn:
            return None

        try:
            search_filter = f"(&(objectClass=computer)(|(cn={computer_name})(sAMAccountName={computer_name}$)))"

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=['cn', 'operatingSystem', 'operatingSystemVersion',
                            'lastLogonTimestamp', 'userAccountControl', 'dNSHostName'],
                size_limit=1
            )

            if not conn.entries:
                return None

            entry = conn.entries[0]

            info = {
                'name': self._sanitize_ldap_string(str(entry.cn)) if hasattr(entry, 'cn') else computer_name,
                'dns_hostname': self._sanitize_ldap_string(str(entry.dNSHostName)) if hasattr(entry,
                                                                                              'dNSHostName') else None,
                'os': self._sanitize_ldap_string(str(entry.operatingSystem)) if hasattr(entry,
                                                                                        'operatingSystem') else 'Unknown',
                'os_version': self._sanitize_ldap_string(str(entry.operatingSystemVersion)) if hasattr(entry,
                                                                                                       'operatingSystemVersion') else None,
                'enabled': True,
                'last_logon': None
            }

            if hasattr(entry, 'userAccountControl'):
                uac = int(entry.userAccountControl.value)
                info['enabled'] = not (uac & 0x0002)

            if hasattr(entry, 'lastLogonTimestamp') and entry.lastLogonTimestamp.value:
                try:
                    info['last_logon'] = self._filetime_to_datetime(int(entry.lastLogonTimestamp.value))
                except:
                    pass

            return info

        except Exception as e:
            self.logger.error(f"Ошибка получения информации о компьютере {computer_name}: {type(e).__name__}")
            return None

    def _cache_refresh_loop(self) -> None:
        """Периодическое обновление кэша"""
        while self.running:
            time.sleep(self.cache_ttl // 2)

            with self._lock:
                now = time.time()
                for cache_dict in [self.user_cache, self.group_cache, self.computer_cache]:
                    expired = [
                        key for key, data in cache_dict.items()
                        if now - data.get('timestamp', 0) > self.cache_ttl * 2
                    ]
                    for key in expired:
                        del cache_dict[key]

    def search_users(self, query: str, limit: int = 10) -> List[Dict]:
        """Поиск пользователей в LDAP"""
        conn = self._get_ldap_connection()
        if not conn:
            return []

        try:
            search_filter = f"(&(objectClass=user)(|(cn=*{query}*)(sAMAccountName=*{query}*)(mail=*{query}*)))"

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=['sAMAccountName', 'displayName', 'mail', 'department', 'title'],
                size_limit=limit
            )

            results = []
            for entry in conn.entries:
                results.append({
                    'username': self._sanitize_ldap_string(str(entry.sAMAccountName)) if hasattr(entry,
                                                                                                 'sAMAccountName') else '',
                    'display_name': self._sanitize_ldap_string(str(entry.displayName)) if hasattr(entry,
                                                                                                  'displayName') else '',
                    'email': self._sanitize_ldap_string(str(entry.mail)) if hasattr(entry, 'mail') else '',
                    'department': self._sanitize_ldap_string(str(entry.department)) if hasattr(entry,
                                                                                               'department') else '',
                    'title': self._sanitize_ldap_string(str(entry.title)) if hasattr(entry, 'title') else ''
                })

            return results

        except Exception as e:
            self.logger.error(f"Ошибка поиска пользователей: {type(e).__name__}")
            return []

    def get_domain_controllers(self) -> List[str]:
        """Получение списка контроллеров домена"""
        conn = self._get_ldap_connection()
        if not conn:
            return []

        try:
            search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=['cn', 'dNSHostName'],
                size_limit=10
            )

            dcs = []
            for entry in conn.entries:
                if hasattr(entry, 'dNSHostName'):
                    dcs.append(self._sanitize_ldap_string(str(entry.dNSHostName), 100))
                elif hasattr(entry, 'cn'):
                    dcs.append(self._sanitize_ldap_string(str(entry.cn), 100))

            return dcs

        except Exception as e:
            self.logger.error(f"Ошибка получения контроллеров домена: {type(e).__name__}")
            return []

    def clear_cache(self) -> None:
        """Очистка всего кэша"""
        with self._lock:
            self.user_cache.clear()
            self.group_cache.clear()
            self.computer_cache.clear()
        self.logger.info("Кэш LDAP очищен")


# ============================================================
# 8️⃣ EMAIL УГРОЗЫ
# ============================================================


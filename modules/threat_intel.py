#!/usr/bin/env python3
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
from shard_enterprise_complete import AttackType, AlertSeverity
import os, time, threading, queue, json, re, requests
from typing import Dict, List, Optional, Any, Set, Tuple
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

class ThreatIntelligence(BaseModule):
    """Интеграция с базами репутации IP (полная реальная версия)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ThreatIntel", config, event_bus, logger)

        # API ключи
        self.abuseipdb_key = config.get('threat_intel.abuseipdb_key') or os.environ.get('ABUSEIPDB_KEY', '')
        self.virustotal_key = config.get('threat_intel.virustotal_key') or os.environ.get('VIRUSTOTAL_KEY', '')
        self.alienvault_key = config.get('threat_intel.alienvault_key') or os.environ.get('ALIENVAULT_KEY', '')
        self.ipinfo_token = config.get('threat_intel.ipinfo_token') or os.environ.get('IPINFO_TOKEN', '')

        # Геолокация
        self.geoip_db_path = config.get('threat_intel.geoip_db') or '/usr/share/GeoIP/GeoLite2-City.mmdb'
        self.geoip_city_path = config.get('threat_intel.geoip_city_db') or '/usr/share/GeoIP/GeoLite2-City.mmdb'
        self.geoip_asn_path = config.get('threat_intel.geoip_asn_db') or '/usr/share/GeoIP/GeoLite2-ASN.mmdb'
        self.geoip_reader = None
        self.geoip_asn_reader = None

        # Кэш
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl = 3600  # 1 час
        self.geo_cache: Dict[str, Dict] = {}
        self.geo_cache_ttl = 86400  # 24 часа для геолокации

        # Блокировки
        self._lock = threading.RLock()
        self._geo_lock = threading.RLock()

        # HTTP сессия
        self._session = None

        # Executor для асинхронных запросов
        self._executor = None
        self._pending_checks: Set[str] = set()
        self._pending_lock = threading.RLock()

        # Списки известных вредоносных IP (локальный кэш)
        self.known_malicious_ips: Set[str] = set()
        self.known_tor_exit_nodes: Set[str] = set()
        self.known_vpn_ips: Set[str] = set()

        # Инициализация
        self._init_http_session()
        self._init_geoip()
        self._load_local_lists()

        # Подписки на события
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('packet.received', self.on_packet)
        self.event_bus.subscribe('threat_intel.check_ip', self.on_check_ip_request)

    def _init_http_session(self) -> None:
        """Инициализация HTTP сессии"""
        if requests:
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': 'SHARD-SIEM/2.0 (+https://github.com/shard/siem)'
            })
            # Настройка таймаутов и retry
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            retry_strategy = Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)

    def _init_geoip(self) -> None:
        """Инициализация GeoIP баз данных"""
        # Пробуем загрузить MaxMind GeoIP2
        try:
            import geoip2.database

            # City база
            if Path(self.geoip_city_path).exists():
                self.geoip_reader = geoip2.database.Reader(self.geoip_city_path)
                self.logger.info(f"GeoIP City база загружена: {self.geoip_city_path}")
            elif Path(self.geoip_db_path).exists():
                self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                self.logger.info(f"GeoIP база загружена: {self.geoip_db_path}")
            else:
                self.logger.warning(
                    f"GeoIP база не найдена. Скачайте с https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")

            # ASN база
            if Path(self.geoip_asn_path).exists():
                self.geoip_asn_reader = geoip2.database.Reader(self.geoip_asn_path)
                self.logger.info(f"GeoIP ASN база загружена: {self.geoip_asn_path}")

        except ImportError:
            self.logger.warning("geoip2 не установлен. Установите: pip install geoip2")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки GeoIP: {e}")

        # Fallback на geoip2 (бесплатная альтернатива)
        if not self.geoip_reader:
            try:
                import geoip2
                # Пробуем стандартные пути
                standard_paths = [
                    '/usr/local/share/GeoIP/GeoLite2-City.mmdb',
                    '/usr/share/GeoIP/GeoLite2-City.mmdb',
                    '/var/lib/GeoIP/GeoLite2-City.mmdb',
                    os.path.expanduser('~/.geoip/GeoLite2-City.mmdb')
                ]
                for path in standard_paths:
                    if Path(path).exists():
                        import geoip2.database
                        self.geoip_reader = geoip2.database.Reader(path)
                        self.geoip_db_path = path
                        self.logger.info(f"GeoIP база найдена: {path}")
                        break
            except:
                pass

    def _load_local_lists(self) -> None:
        """Загрузка локальных списков известных вредоносных IP"""
        # Списки можно загружать из файлов или URL
        list_paths = [
            Path('data/tor_exit_nodes.txt'),
            Path('data/known_malicious.txt'),
            Path('data/vpn_ips.txt')
        ]

        for path in list_paths:
            if path.exists():
                try:
                    with open(path, 'r') as f:
                        ips = {line.strip() for line in f if line.strip() and not line.startswith('#')}
                        if 'tor' in path.name:
                            self.known_tor_exit_nodes.update(ips)
                            self.logger.info(f"Загружено {len(ips)} Tor exit nodes")
                        elif 'malicious' in path.name:
                            self.known_malicious_ips.update(ips)
                            self.logger.info(f"Загружено {len(ips)} известных вредоносных IP")
                        elif 'vpn' in path.name:
                            self.known_vpn_ips.update(ips)
                            self.logger.info(f"Загружено {len(ips)} VPN IP")
                except Exception as e:
                    self.logger.debug(f"Ошибка загрузки списка {path}: {e}")

        # Загрузка из URL если списки пусты
        if not self.known_tor_exit_nodes:
            threading.Thread(target=self._download_tor_exit_list, daemon=True).start()

    def _download_tor_exit_list(self) -> None:
        """Скачивание списка Tor exit nodes (с проверкой сертификата)"""
        try:
            if self._session:
                # Используем HTTPS с проверкой сертификата
                response = self._session.get(
                    'https://check.torproject.org/torbulkexitlist',
                    timeout=30,
                    verify=True  # Явно включаем проверку SSL
                )
                if response.status_code == 200:
                    ips = set()
                    for line in response.text.strip().split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Валидация IP перед добавлением
                            if self._is_public_ip(line):
                                ips.add(line)

                    with self._lock:
                        self.known_tor_exit_nodes.update(ips)
                    self.logger.info(f"Скачано {len(ips)} Tor exit nodes (проверено SSL)")
            else:
                self.logger.warning("HTTP сессия не инициализирована")
        except Exception as e:
            self.logger.debug(f"Ошибка скачивания Tor списка: {e}")

    def start(self) -> None:
        """Запуск модуля"""
        self.running = True

        # Создаём executor при старте
        self._executor = ThreadPoolExecutor(
            max_workers=8,
            thread_name_prefix="ThreatIntel"
        )

        # Запускаем фоновые потоки
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        threading.Thread(target=self._cache_warmup_loop, daemon=True).start()

        self.logger.info(
            f"Threat Intelligence запущен:\n"
            f"  - AbuseIPDB: {bool(self.abuseipdb_key)}\n"
            f"  - VirusTotal: {bool(self.virustotal_key)}\n"
            f"  - AlienVault: {bool(self.alienvault_key)}\n"
            f"  - GeoIP: {bool(self.geoip_reader)}\n"
            f"  - Локальные списки: {len(self.known_malicious_ips)} malicious, "
            f"{len(self.known_tor_exit_nodes)} Tor, {len(self.known_vpn_ips)} VPN"
        )

    def stop(self) -> None:
        """Остановка модуля с graceful shutdown"""
        self.running = False

        # Закрываем HTTP сессию
        if self._session:
            try:
                self._session.close()
            except:
                pass

        # Graceful shutdown executor
        if self._executor is not None:
            try:
                # Пробуем разные варианты shutdown
                if hasattr(self._executor, 'shutdown'):
                    import sys
                    if sys.version_info >= (3, 9):
                        try:
                            self._executor.shutdown(wait=False, cancel_futures=True)
                        except:
                            pass
                    # Просто shutdown без аргументов
                    try:
                        self._executor.shutdown()
                    except:
                        pass
            except Exception as e:
                self.logger.debug(f"Ошибка при остановке executor: {e}")
            finally:
                self._executor = None

        # Закрываем GeoIP
        if self.geoip_reader:
            try:
                self.geoip_reader.close()
            except:
                pass

        if self.geoip_asn_reader:
            try:
                self.geoip_asn_reader.close()
            except:
                pass

        self.logger.info("Threat Intelligence остановлен")

    def on_alert(self, alert: Dict) -> None:
        """Проверка IP при алерте"""
        src_ip = alert.get('src_ip', '')
        dst_ip = alert.get('dst_ip', '')

        # Проверяем оба IP если они публичные
        for ip in (src_ip, dst_ip):
            if ip and self._is_public_ip(ip):
                self._executor.submit(self._check_ip_and_enrich_alert, ip, alert)

    def _check_ip_and_enrich_alert(self, ip: str, alert: Dict) -> None:
        """Проверка IP и обогащение алерта"""
        result = self.check_ip(ip)

        if result['is_malicious']:
            alert['threat_intel'] = result
            alert['score'] = min(1.0, alert.get('score', 0) + result['score'] * 0.3)

            # Добавляем геолокацию
            if 'geo' in result:
                alert['geo_location'] = result['geo']

            self.logger.warning(f"IP {ip} найден в threat intelligence: score={result['score']:.2f}")

    def on_packet(self, data: Dict) -> None:
        """Проверка IP из трафика"""
        if not self._executor:
            return

        src_ip = data.get('src_ip', '')
        dst_ip = data.get('dst_ip', '')

        for ip in (src_ip, dst_ip):
            if ip and self._is_public_ip(ip):
                # Проверяем не чаще чем раз в минуту
                with self._lock:
                    if ip in self.cache:
                        last_check = self.cache[ip].get('timestamp', 0)
                        if time.time() - last_check < 60:
                            continue

                # Проверяем, не проверяется ли уже этот IP
                with self._pending_lock:
                    if ip in self._pending_checks:
                        continue
                    self._pending_checks.add(ip)

                # Асинхронная проверка
                self._executor.submit(self._check_and_alert_wrapper, ip)

    def on_check_ip_request(self, data: Dict) -> None:
        """Обработка явного запроса на проверку IP"""
        ip = data.get('ip', '')
        request_id = data.get('request_id', '')

        if ip and self._is_public_ip(ip):
            result = self.check_ip(ip)
            self.event_bus.publish('threat_intel.check_ip.response', {
                'request_id': request_id,
                'ip': ip,
                'result': result
            })

    def _check_and_alert_wrapper(self, ip: str) -> None:
        """Обёртка для проверки с очисткой pending"""
        try:
            self._check_and_alert(ip)
        finally:
            with self._pending_lock:
                self._pending_checks.discard(ip)

    def _check_and_alert(self, ip: str) -> None:
        """Проверка IP и отправка алерта при обнаружении"""
        result = self.check_ip(ip)

        if result['is_malicious']:
            alert = {
                'timestamp': time.time(),
                'src_ip': ip,
                'attack_type': AttackType.BOTNET.value,
                'score': result['score'],
                'confidence': result.get('confidence', 0.8),
                'is_attack': True,
                'threat_intel': result,
                'severity': AlertSeverity.HIGH.value if result['score'] > 0.7 else AlertSeverity.MEDIUM.value,
                'explanation': f"IP {ip} обнаружен в базе угроз (score: {result['score']:.2f})"
            }

            # Добавляем информацию об источнике обнаружения
            if result.get('sources'):
                alert['explanation'] += f" Источники: {', '.join(result['sources'])}"

            # Добавляем геолокацию
            if result.get('geo', {}).get('country'):
                alert['geo_location'] = result['geo']

            self.event_bus.publish('alert.detected', alert)

    def check_ip(self, ip: str) -> Dict:
        """Полная проверка IP через все доступные источники (параллельные запросы)"""

        # Проверка кэша
        with self._lock:
            if ip in self.cache:
                cached = self.cache[ip]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached['result'].copy()

        # Быстрая проверка локальных списков
        quick_result = self._check_local_lists(ip)
        if quick_result['is_malicious'] and quick_result['score'] > 0.8:
            result = quick_result
        else:
            result = {
                'is_malicious': False,
                'score': quick_result['score'],
                'confidence': quick_result['confidence'],
                'sources': quick_result['sources'],
                'country': None,
                'city': None,
                'latitude': None,
                'longitude': None,
                'timezone': None,
                'isp': None,
                'asn': None,
                'usage_type': None,
                'is_tor': quick_result.get('is_tor', False),
                'is_vpn': quick_result.get('is_vpn', False),
                'is_proxy': False,
                'is_hosting': False,
                'categories': quick_result.get('categories', []),
                'reports': 0,
                'last_reported': None,
                'details': {},
                'geo': {},
                'reputation_services': {}
            }

            # Параллельные запросы к внешним API
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {}

                # Геолокация
                futures['geo'] = executor.submit(self.get_geo_location, ip)

                # AbuseIPDB
                if self.abuseipdb_key:
                    futures['abuse'] = executor.submit(self._check_abuseipdb_full, ip)

                # VirusTotal
                if self.virustotal_key:
                    futures['vt'] = executor.submit(self._check_virustotal_full, ip)

                # AlienVault
                if self.alienvault_key:
                    futures['otx'] = executor.submit(self._check_alienvault, ip)

                # IPinfo
                if self.ipinfo_token:
                    futures['ipinfo'] = executor.submit(self._check_ipinfo, ip)

                # Сбор результатов с таймаутом
                for key, future in futures.items():
                    try:
                        data = future.result(timeout=5)
                        if key == 'geo' and data:
                            result['country'] = data.get('country')
                            result['city'] = data.get('city')
                            result['latitude'] = data.get('latitude')
                            result['longitude'] = data.get('longitude')
                            result['timezone'] = data.get('timezone')
                            result['isp'] = data.get('isp')
                            result['asn'] = data.get('asn')
                            result['is_hosting'] = data.get('is_hosting', False)
                            result['geo'] = data

                        elif key == 'abuse' and data:
                            result['reputation_services']['abuseipdb'] = data
                            confidence_score = data.get('score', 0)
                            if confidence_score > 50:
                                result['is_malicious'] = True
                            result['score'] = max(result['score'], confidence_score / 100)
                            result['confidence'] = max(result['confidence'], confidence_score / 100)
                            result['sources'].append('AbuseIPDB')
                            result['reports'] = max(result['reports'], data.get('total_reports', 0))
                            result['last_reported'] = data.get('last_reported')
                            if data.get('categories'):
                                result['categories'].extend(data['categories'])
                            if data.get('is_tor'):
                                result['is_tor'] = True

                        elif key == 'vt' and data:
                            result['reputation_services']['virustotal'] = data
                            malicious_count = data.get('malicious', 0)
                            suspicious_count = data.get('suspicious', 0)
                            total_votes = data.get('total', 0)
                            if total_votes > 0:
                                vt_score = (malicious_count + suspicious_count * 0.5) / total_votes
                            else:
                                vt_score = 0.0
                            if malicious_count > 0:
                                result['is_malicious'] = True
                            result['score'] = max(result['score'], vt_score)
                            result['confidence'] = max(result['confidence'], vt_score)
                            result['sources'].append('VirusTotal')
                            if data.get('categories'):
                                result['categories'].extend(data['categories'])

                        elif key == 'otx' and data:
                            result['reputation_services']['alienvault'] = data
                            pulse_count = data.get('pulse_count', 0)
                            if pulse_count > 0:
                                result['is_malicious'] = True
                                otx_score = min(1.0, pulse_count / 10)
                                result['score'] = max(result['score'], otx_score)
                                result['confidence'] = max(result['confidence'], 0.7)
                                result['sources'].append('AlienVault OTX')
                                if data.get('tags'):
                                    result['categories'].extend(data['tags'])

                        elif key == 'ipinfo' and data:
                            result['isp'] = data.get('org', result['isp'])
                            result['asn'] = data.get('asn', result['asn'])
                            result['is_hosting'] = data.get('hosting', result['is_hosting'])
                            result['is_vpn'] = data.get('vpn', result['is_vpn'])
                            result['is_proxy'] = data.get('proxy', result['is_proxy'])
                            result['is_tor'] = data.get('tor', result['is_tor'])

                    except TimeoutError:  # ← ИСПРАВЛЕНО: было FutureTimeoutError
                        self.logger.debug(f"Таймаут запроса {key} для IP {ip}")
                    except Exception as e:
                        self.logger.debug(f"Ошибка запроса {key} для IP {ip}: {type(e).__name__}")

        # Нормализация score
        result['score'] = min(1.0, result['score'])

        if len(result['sources']) >= 2:
            result['confidence'] = min(1.0, result['confidence'] + 0.1)

        # Сохраняем в кэш
        with self._lock:
            self.cache[ip] = {
                'result': result.copy(),
                'timestamp': time.time()
            }

        return result

    def _check_local_lists(self, ip: str) -> Dict:
        """Проверка IP по локальным спискам"""
        result = {
            'is_malicious': False,
            'score': 0.0,
            'confidence': 0.0,
            'sources': [],
            'is_tor': False,
            'is_vpn': False,
            'categories': []
        }

        # Проверка Tor exit nodes
        if ip in self.known_tor_exit_nodes:
            result['is_malicious'] = True
            result['is_tor'] = True
            result['score'] = max(result['score'], 0.6)
            result['confidence'] = 0.9
            result['sources'].append('Tor Exit List')
            result['categories'].append('Tor')

        # Проверка известных вредоносных IP
        if ip in self.known_malicious_ips:
            result['is_malicious'] = True
            result['score'] = max(result['score'], 0.8)
            result['confidence'] = 0.85
            result['sources'].append('Local Blocklist')
            result['categories'].append('Malicious')

        # Проверка VPN
        if ip in self.known_vpn_ips:
            result['is_vpn'] = True
            result['score'] = max(result['score'], 0.4)
            result['sources'].append('VPN List')
            result['categories'].append('VPN')

        return result

    def get_geo_location(self, ip: str) -> Dict:
        """Получение геолокации IP из разных источников"""
        # Проверка кэша геолокации
        with self._geo_lock:
            if ip in self.geo_cache:
                cached = self.geo_cache[ip]
                if time.time() - cached.get('timestamp', 0) < self.geo_cache_ttl:
                    return cached['data'].copy()

        result = {
            'country': None,
            'country_code': None,
            'region': None,
            'city': None,
            'postal_code': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None,
            'org': None,
            'asn': None,
            'as_org': None,
            'is_anonymous': False,
            'is_hosting': False,
            'is_proxy': False,
            'is_tor': False,
            'is_vpn': False,
            'source': 'unknown'
        }

        # 1. Локальная GeoIP база MaxMind
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)
                result['country'] = response.country.name
                result['country_code'] = response.country.iso_code
                result['city'] = response.city.name
                result['postal_code'] = response.postal.code
                result['latitude'] = response.location.latitude
                result['longitude'] = response.location.longitude
                result['timezone'] = response.location.time_zone

                # Континент и регион
                if hasattr(response, 'continent'):
                    result['continent'] = response.continent.name
                if hasattr(response, 'subdivisions') and response.subdivisions:
                    result['region'] = response.subdivisions[0].name

                # Признаки
                if hasattr(response, 'traits'):
                    result['is_anonymous'] = getattr(response.traits, 'is_anonymous_proxy', False)
                    result['is_hosting'] = getattr(response.traits, 'is_hosting_provider', False)
                    result['is_tor'] = getattr(response.traits, 'is_tor_exit_node', False)

                result['source'] = 'MaxMind GeoIP2'
            except Exception as e:
                self.logger.debug(f"GeoIP ошибка для {ip}: {e}")

        # 2. ASN информация
        if self.geoip_asn_reader:
            try:
                asn_response = self.geoip_asn_reader.asn(ip)
                result['asn'] = asn_response.autonomous_system_number
                result['as_org'] = asn_response.autonomous_system_organization
            except:
                pass

        # 3. Fallback на ip-api.com (бесплатный, без ключа)
        if not result['country'] and self._session:
            try:
                response = self._session.get(
                    f'http://ip-api.com/json/{ip}',
                    params={
                        'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query'
                    },
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        result['country'] = data.get('country')
                        result['country_code'] = data.get('countryCode')
                        result['region'] = data.get('regionName')
                        result['city'] = data.get('city')
                        result['postal_code'] = data.get('zip')
                        result['latitude'] = data.get('lat')
                        result['longitude'] = data.get('lon')
                        result['timezone'] = data.get('timezone')
                        result['isp'] = data.get('isp')
                        result['org'] = data.get('org')
                        result['asn'] = data.get('as')
                        result['is_proxy'] = data.get('proxy', False)
                        result['is_hosting'] = data.get('hosting', False)
                        result['source'] = 'ip-api.com'
            except Exception as e:
                self.logger.debug(f"ip-api.com ошибка: {e}")

        # 4. Fallback на ipapi.co
        if not result['country'] and self._session:
            try:
                response = self._session.get(
                    f'https://ipapi.co/{ip}/json/',
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    if not data.get('error'):
                        result['country'] = data.get('country_name')
                        result['country_code'] = data.get('country_code')
                        result['region'] = data.get('region')
                        result['city'] = data.get('city')
                        result['postal_code'] = data.get('postal')
                        result['latitude'] = data.get('latitude')
                        result['longitude'] = data.get('longitude')
                        result['timezone'] = data.get('timezone')
                        result['isp'] = data.get('org')
                        result['asn'] = data.get('asn')
                        result['source'] = 'ipapi.co'
            except Exception as e:
                self.logger.debug(f"ipapi.co ошибка: {e}")

        # 5. IPinfo (если есть токен)
        if self.ipinfo_token and not result['isp'] and self._session:
            try:
                response = self._session.get(
                    f'https://ipinfo.io/{ip}/json',
                    headers={'Authorization': f'Bearer {self.ipinfo_token}'},
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    result['country'] = data.get('country', result['country'])
                    result['city'] = data.get('city', result['city'])
                    result['region'] = data.get('region', result['region'])
                    result['postal_code'] = data.get('postal', result['postal_code'])

                    # Парсинг локации
                    loc = data.get('loc', '')
                    if loc and ',' in loc:
                        lat, lon = loc.split(',')
                        result['latitude'] = float(lat)
                        result['longitude'] = float(lon)

                    result['isp'] = data.get('org', result['isp'])
                    result['asn'] = data.get('asn', {}).get('asn', result['asn'])
                    result['timezone'] = data.get('timezone', result['timezone'])

                    # Признаки из privacy информации
                    privacy = data.get('privacy', {})
                    result['is_vpn'] = privacy.get('vpn', False)
                    result['is_proxy'] = privacy.get('proxy', False)
                    result['is_tor'] = privacy.get('tor', False)
                    result['is_hosting'] = privacy.get('hosting', False)

                    result['source'] = 'ipinfo.io'
            except Exception as e:
                self.logger.debug(f"ipinfo.io ошибка: {e}")

        # Сохраняем в кэш
        with self._geo_lock:
            self.geo_cache[ip] = {
                'data': result.copy(),
                'timestamp': time.time()
            }

        return result

    def _check_abuseipdb_full(self, ip: str) -> Optional[Dict]:
        """Расширенная проверка через AbuseIPDB"""
        if not self.abuseipdb_key or not self._session:
            return None

        try:
            # Основная проверка
            response = self._session.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': True
                },
                headers={
                    'Key': self.abuseipdb_key,
                    'Accept': 'application/json'
                },
                timeout=5
            )

            if response.status_code != 200:
                if response.status_code == 429:
                    self.logger.warning("AbuseIPDB: превышен лимит запросов")
                return None

            data = response.json().get('data', {})

            result = {
                'score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'last_reported': data.get('lastReportedAt'),
                'country': data.get('countryCode'),
                'isp': data.get('isp'),
                'domain': data.get('domain'),
                'usage_type': data.get('usageType'),
                'is_public': data.get('isPublic', False),
                'is_whitelisted': data.get('isWhitelisted', False),
                'is_tor': data.get('isTor', False),
                'categories': []
            }

            # Получаем детали отчётов
            if data.get('reports'):
                categories = set()
                for report in data['reports'][:10]:
                    for cat in report.get('categories', []):
                        categories.add(self._abuseipdb_category_name(cat))
                result['categories'] = list(categories)

            return result

        except Exception as e:
            self.logger.debug(f"AbuseIPDB ошибка: {e}")
            return None

    def _abuseipdb_category_name(self, cat_id: int) -> str:
        """Получение названия категории AbuseIPDB"""
        categories = {
            3: 'Fraud Orders',
            4: 'DDoS Attack',
            5: 'FTP Brute-Force',
            6: 'Ping of Death',
            7: 'Phishing',
            8: 'Fraud VoIP',
            9: 'Open Proxy',
            10: 'Web Spam',
            11: 'Email Spam',
            12: 'Blog Spam',
            13: 'VPN IP',
            14: 'Port Scan',
            15: 'Hacking',
            16: 'SQL Injection',
            17: 'Spoofing',
            18: 'Brute-Force',
            19: 'Bad Web Bot',
            20: 'Exploited Host',
            21: 'Web App Attack',
            22: 'SSH',
            23: 'IoT Targeted'
        }
        return categories.get(cat_id, f'Unknown({cat_id})')

    def _check_virustotal_full(self, ip: str) -> Optional[Dict]:
        """Расширенная проверка через VirusTotal"""
        if not self.virustotal_key or not self._session:
            return None

        try:
            response = self._session.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': self.virustotal_key},
                timeout=5
            )

            if response.status_code != 200:
                if response.status_code == 429:
                    self.logger.warning("VirusTotal: превышен лимит запросов")
                return None

            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})

            # Статистика детектирования
            stats = attributes.get('last_analysis_stats', {})

            result = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'timeout': stats.get('timeout', 0),
                'total': sum(stats.values()),
                'country': attributes.get('country'),
                'asn': attributes.get('asn'),
                'network': attributes.get('network'),
                'reputation': attributes.get('reputation', 0),
                'categories': [],
                'tags': attributes.get('tags', [])
            }

            # Собираем категории из результатов
            results = attributes.get('last_analysis_results', {})
            for engine, engine_result in results.items():
                category = engine_result.get('category')
                if category in ['malicious', 'suspicious']:
                    result_name = engine_result.get('result', '')
                    if result_name:
                        result['categories'].append(result_name)

            result['categories'] = list(set(result['categories']))

            return result

        except Exception as e:
            self.logger.debug(f"VirusTotal ошибка: {e}")
            return None

    def _check_alienvault(self, ip: str) -> Optional[Dict]:
        """Проверка через AlienVault OTX"""
        if not self.alienvault_key or not self._session:
            return None

        try:
            response = self._session.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                headers={'X-OTX-API-KEY': self.alienvault_key},
                timeout=5
            )

            if response.status_code != 200:
                return None

            data = response.json()

            result = {
                'pulse_count': data.get('pulse_info', {}).get('count', 0),
                'pulses': [],
                'tags': [],
                'country': data.get('country_name'),
                'city': data.get('city'),
                'asn': data.get('asn')
            }

            # Собираем теги из пульсов
            pulses = data.get('pulse_info', {}).get('pulses', [])
            for pulse in pulses[:10]:
                result['tags'].extend(pulse.get('tags', []))
                result['pulses'].append({
                    'name': pulse.get('name'),
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'adversary': pulse.get('adversary')
                })

            result['tags'] = list(set(result['tags']))

            return result

        except Exception as e:
            self.logger.debug(f"AlienVault ошибка: {e}")
            return None

    def _check_ipinfo(self, ip: str) -> Optional[Dict]:
        """Проверка через IPinfo"""
        if not self.ipinfo_token or not self._session:
            return None

        try:
            response = self._session.get(
                f'https://ipinfo.io/{ip}',
                headers={'Authorization': f'Bearer {self.ipinfo_token}'},
                timeout=3
            )

            if response.status_code != 200:
                return None

            data = response.json()

            return {
                'org': data.get('org'),
                'asn': data.get('asn', {}).get('asn') if isinstance(data.get('asn'), dict) else data.get('asn'),
                'hosting': data.get('privacy', {}).get('hosting', False),
                'vpn': data.get('privacy', {}).get('vpn', False),
                'proxy': data.get('privacy', {}).get('proxy', False),
                'tor': data.get('privacy', {}).get('tor', False),
                'relay': data.get('privacy', {}).get('relay', False)
            }

        except Exception as e:
            self.logger.debug(f"IPinfo ошибка: {e}")
            return None

    def _is_public_ip(self, ip: str) -> bool:
        """Проверка, является ли IP публичным"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first = int(parts[0])
            second = int(parts[1]) if len(parts) > 1 else 0

            # Приватные диапазоны
            if first == 10:
                return False
            if first == 172 and 16 <= second <= 31:
                return False
            if first == 192 and second == 168:
                return False
            if first == 127:
                return False
            if first == 0:
                return False
            if first >= 224:
                return False
            if first == 169 and second == 254:
                return False
            if first == 100 and 64 <= second <= 127:  # CGNAT
                return False

            return True
        except (ValueError, IndexError):
            return False

    def _cleanup_loop(self) -> None:
        """Очистка устаревшего кэша (исправлено - безопасное удаление)"""
        while self.running:
            time.sleep(300)  # Каждые 5 минут
            now = time.time()

            # Собираем ключи для удаления
            expired_threat = []
            expired_geo = []

            with self._lock:
                for ip, data in self.cache.items():
                    if now - data['timestamp'] > self.cache_ttl * 2:
                        expired_threat.append(ip)

            with self._geo_lock:
                for ip, data in self.geo_cache.items():
                    if now - data['timestamp'] > self.geo_cache_ttl * 2:
                        expired_geo.append(ip)

            # Удаляем под отдельными блокировками
            if expired_threat:
                with self._lock:
                    for ip in expired_threat:
                        if ip in self.cache:
                            del self.cache[ip]
                self.logger.debug(f"Очищено {len(expired_threat)} записей из кэша ThreatIntel")

            if expired_geo:
                with self._geo_lock:
                    for ip in expired_geo:
                        if ip in self.geo_cache:
                            del self.geo_cache[ip]
                self.logger.debug(f"Очищено {len(expired_geo)} записей из кэша геолокации")

    def _cache_warmup_loop(self) -> None:
        """Периодический прогрев кэша важных IP"""
        while self.running:
            time.sleep(3600)  # Раз в час
            # Можно добавить прогрев для часто встречающихся IP
            pass

    def get_cache_stats(self) -> Dict:
        """Получить статистику кэша"""
        with self._lock:
            with self._pending_lock:
                with self._geo_lock:
                    return {
                        'threat_cache_size': len(self.cache),
                        'geo_cache_size': len(self.geo_cache),
                        'pending_checks': len(self._pending_checks),
                        'cache_ttl': self.cache_ttl,
                        'geo_cache_ttl': self.geo_cache_ttl,
                        'local_malicious': len(self.known_malicious_ips),
                        'local_tor': len(self.known_tor_exit_nodes),
                        'local_vpn': len(self.known_vpn_ips)
                    }

    def bulk_check_ips(self, ips: List[str]) -> Dict[str, Dict]:
        """Массовая проверка списка IP (используем существующий executor)"""
        results = {}
        public_ips = [ip for ip in ips if self._is_public_ip(ip)]

        if not public_ips:
            return results

        # Используем СУЩЕСТВУЮЩИЙ executor вместо создания нового
        if self._executor is None:
            # Если executor ещё не создан - создаём
            self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ThreatIntel")

        futures = {}
        for ip in public_ips:
            futures[self._executor.submit(self.check_ip, ip)] = ip

        for future in futures:
            ip = futures[future]
            try:
                results[ip] = future.result(timeout=10)
            except TimeoutError:
                results[ip] = {'error': 'timeout', 'is_malicious': False, 'score': 0}
            except Exception as e:
                results[ip] = {'error': str(e)[:100], 'is_malicious': False, 'score': 0}

        return results

    def add_to_local_blocklist(self, ip: str, reason: str = 'manual') -> None:
        """Добавить IP в локальный блок-лист (исправлено - инвалидация кэша)"""
        if not self._is_public_ip(ip):
            self.logger.warning(f"IP {ip} не является публичным, не добавлен в блок-лист")
            return

        with self._lock:
            self.known_malicious_ips.add(ip)

            # ИНВАЛИДАЦИЯ КЭША для этого IP
            if ip in self.cache:
                del self.cache[ip]
                self.logger.debug(f"Кэш для IP {ip} инвалидирован после добавления в блок-лист")

        # Сохраняем в файл
        try:
            list_path = Path('data/known_malicious.txt')
            list_path.parent.mkdir(parents=True, exist_ok=True)
            with open(list_path, 'a', encoding='utf-8') as f:
                f.write(f"{ip} # {reason} - {datetime.now().isoformat()}\n")

            self.logger.info(f"IP {ip} добавлен в локальный блок-лист (причина: {reason})")
        except Exception as e:
            self.logger.error(f"Ошибка сохранения блок-листа: {e}")

    def remove_from_local_blocklist(self, ip: str) -> bool:
        """Удалить IP из локального блок-листа (с инвалидацией кэша)"""
        with self._lock:
            if ip in self.known_malicious_ips:
                self.known_malicious_ips.remove(ip)

                # Инвалидация кэша
                if ip in self.cache:
                    del self.cache[ip]

                return True
        return False



# ============================================================
# 3️⃣ ОБНАРУЖЕНИЕ УТЕЧКИ ДАННЫХ
# ============================================================


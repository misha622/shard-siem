#!/usr/bin/env python3
"""SHARD EDRIntegration Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import os, time, threading, queue, json, re, subprocess
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

class EDRIntegration(BaseModule):
    """Интеграция с EDR/антивирусами через Windows Event Logs / Sysmon / WMI (полная реальная версия)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("EDR", config, event_bus, logger)

        # Буферы событий
        self.process_events: deque = deque(maxlen=5000)
        self.file_events: deque = deque(maxlen=2000)
        self.registry_events: deque = deque(maxlen=2000)
        self.network_events: deque = deque(maxlen=2000)
        self.dns_events: deque = deque(maxlen=1000)
        self.image_load_events: deque = deque(maxlen=1000)

        # Подозрительные процессы и паттерны
        self.suspicious_processes = {
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'schtasks.exe',
            'wmic.exe', 'bitsadmin.exe', 'certutil.exe', 'msiexec.exe',
            'taskkill.exe', 'net.exe', 'net1.exe', 'sc.exe', 'bcdedit.exe',
            'vssadmin.exe', 'wbadmin.exe', 'diskpart.exe', 'format.com',
            'cacls.exe', 'icacls.exe', 'xcopy.exe', 'robocopy.exe',
            'ftp.exe', 'telnet.exe', 'psexec.exe', 'psexesvc.exe',
            'mimikatz.exe', 'procdump.exe', 'lsass.exe', 'lsass.dmp',
            'csrss.exe', 'smss.exe', 'winlogon.exe', 'services.exe'
        }

        self.suspicious_cmdline = [
            '-enc', '-encodedcommand', '-e ', 'iex', 'invoke-',
            'downloadstring', 'downloadfile', 'webclient',
            'net user', 'net group', 'net localgroup',
            'reg add', 'reg delete', 'reg save',
            'schtasks /create', 'taskkill /f',
            'wmic process', 'wmic service',
            'bitsadmin /transfer', 'certutil -urlcache',
            'mshta http', 'mshta javascript',
            'rundll32 javascript', 'rundll32 http',
            'powershell -w hidden', 'powershell -window hidden',
            '-nop -w hidden', '-noprofile -windowstyle hidden',
            'add-mppreference', 'set-mppreference',
            'mimikatz', 'procdump', 'lsass', 'sekurlsa',
            'cobaltstrike', 'metasploit', 'meterpreter',
            'reflectiveloader', 'invoke-mimikatz', 'invoke-shellcode',
            'invoke-reflection', 'invoke-dllinjection',
            'amsiinitfailed', 'amsiscanbuffer', 'amsiopenSession',
            'virtualalloc', 'virtualprotect', 'writeprocessmemory',
            'createremotethread', 'ntallocatevirtualmemory',
            'rtlcreateuserthread', 'etwpcreateetwthread',
            'syscall', 'ntcreatefile', 'ntopenprocess',
            'base64', 'frombase64string', 'tobase64string'
        ]

        self.suspicious_paths = [
            '\\temp\\', '/tmp/', '\\users\\public\\',
            '\\appdata\\local\\temp\\', '\\windows\\temp\\',
            '\\downloads\\', '\\desktop\\',
            '\\programdata\\', '\\recycler\\', '\\$recycle.bin\\',
            '\\windows\\syswow64\\', '\\windows\\system32\\spool\\drivers\\color\\',
            '\\windows\\tasks\\', '\\windows\\system32\\tasks\\',
            '\\microsoft\\windows\\start menu\\programs\\startup\\',
            '\\appdata\\roaming\\', '\\appdata\\locallow\\',
            '\\windows\\fonts\\', '\\windows\\help\\', '\\windows\\inf\\'
        ]

        self.suspicious_registry_keys = [
            '\\software\\microsoft\\windows\\currentversion\\run',
            '\\software\\microsoft\\windows\\currentversion\\runonce',
            '\\software\\microsoft\\windows\\currentversion\\runservices',
            '\\software\\microsoft\\windows nt\\currentversion\\winlogon',
            '\\software\\microsoft\\windows\\currentversion\\policies\\system',
            '\\system\\currentcontrolset\\services',
            '\\software\\microsoft\\windows\\currentversion\\explorer\\usershell folders',
            '\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run',
            '\\software\\microsoft\\windows nt\\currentversion\\windows',
            '\\software\\microsoft\\windows nt\\currentversion\\image file execution options',
            '\\software\\microsoft\\windows\\currentversion\\shell extensions\\approved',
            '\\software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects',
            '\\software\\wow6432node\\microsoft\\windows\\currentversion\\run',
            '\\\\software\\\\classes\\\\*\\\\shell',
            '\\software\\classes\\directory\\shell'
        ]

        self.suspicious_dlls = [
            'ntdll.dll', 'kernel32.dll', 'kernelbase.dll',
            'advapi32.dll', 'user32.dll', 'gdi32.dll',
            'wininet.dll', 'urlmon.dll', 'ws2_32.dll',
            'mimikatz.dll', 'samlib.dll', 'vaultcli.dll',
            'ncrypt.dll', 'cryptdll.dll', 'dpapi.dll'
        ]

        # Настройки Windows Event Log
        self.win_event_logs = config.get('edr.windows_event_logs', [
            'Security',
            'System',
            'Microsoft-Windows-Sysmon/Operational',
            'Windows PowerShell',
            'Microsoft-Windows-WMI-Activity/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-TaskScheduler/Operational',
            'Microsoft-Windows-DNS-Client/Operational'
        ])

        self.poll_interval = config.get('edr.poll_interval', 5)
        self.use_win32evtlog = False
        self.event_log_handles = {}
        self.last_event_ids = {}
        self.last_event_times = {}

        # WMI мониторинг
        self.use_wmi = False
        self.wmi_connection = None
        self.wmi_watchers = []

        # ETW мониторинг (если доступно)
        self.use_etw = False

        # Блокировка
        self._lock = threading.RLock()

        # Инициализация
        self._init_windows_event_log()
        self._init_wmi()

        # Подписки на события
        self.event_bus.subscribe('edr.event', self.on_edr_event)
        self.event_bus.subscribe('sysmon.event', self.on_sysmon_event)
        self.event_bus.subscribe('wmi.event', self.on_wmi_event)

    def _init_windows_event_log(self) -> None:
        """Инициализация чтения Windows Event Log"""
        if sys.platform != 'win32':
            self.logger.debug("Не Windows платформа, чтение Event Log отключено")
            return

        try:
            import win32evtlog
            import win32evtlogutil
            import win32security
            import win32con
            import winerror

            self.use_win32evtlog = True
            self.logger.info("Windows Event Log мониторинг инициализирован")

        except ImportError:
            self.logger.warning("pywin32 не установлен. Установите: pip install pywin32")
            self.use_win32evtlog = False

    def _init_wmi(self) -> None:
        """Инициализация WMI мониторинга"""
        if sys.platform != 'win32':
            return

        try:
            import wmi
            import pythoncom

            pythoncom.CoInitialize()
            self.wmi_connection = wmi.WMI()
            self.use_wmi = True
            self.logger.info("WMI мониторинг инициализирован")

        except ImportError:
            self.logger.debug("wmi не установлен. Установите: pip install wmi")
            self.use_wmi = False
        except Exception as e:
            self.logger.debug(f"Ошибка инициализации WMI: {e}")
            self.use_wmi = False

    def start(self) -> None:
        self.running = True

        # Проверяем платформу перед запуском Windows-специфичных потоков
        if self.use_win32evtlog and sys.platform == 'win32':
            threading.Thread(target=self._windows_event_loop, daemon=True, name="EDR-EventLog").start()
        elif self.use_win32evtlog:
            self.logger.debug("Windows Event Log мониторинг доступен только на Windows")

        if self.use_wmi and sys.platform == 'win32':
            threading.Thread(target=self._wmi_event_loop, daemon=True, name="EDR-WMI").start()
        elif self.use_wmi:
            self.logger.debug("WMI мониторинг доступен только на Windows")

        # Запуск потока анализа (кроссплатформенный)
        threading.Thread(target=self._analysis_loop, daemon=True, name="EDR-Analysis").start()

        self.logger.info("EDR интеграция запущена")

    def stop(self) -> None:
        """Остановка модуля"""
        self.running = False

        # Закрытие хендлов Event Log
        for log_name, handle in self.event_log_handles.items():
            try:
                import win32evtlog
                win32evtlog.CloseEventLog(handle)
            except:
                pass
        self.event_log_handles.clear()

        # Остановка WMI вотчеров
        for watcher in self.wmi_watchers:
            try:
                watcher.stop()
            except:
                pass
        self.wmi_watchers.clear()

    def on_edr_event(self, event: Dict) -> None:
        """Обработка события от EDR"""
        event_type = event.get('event_type', 'unknown')

        if event_type == 'process':
            self._process_process_event(event)
        elif event_type == 'file':
            self._process_file_event(event)
        elif event_type == 'registry':
            self._process_registry_event(event)
        elif event_type == 'network':
            self._process_network_event(event)
        elif event_type == 'dns':
            self._process_dns_event(event)
        elif event_type == 'image_load':
            self._process_image_load_event(event)
        elif event_type == 'login':
            self._process_login_event(event)
        elif event_type == 'failed_login':
            self._process_failed_login_event(event)

    def on_sysmon_event(self, event: Dict) -> None:
        """Обработка события от Sysmon"""
        event_id = event.get('event_id', 0)

        # Sysmon Event IDs
        if event_id == 1:  # Process creation
            self._process_process_event(event)
        elif event_id == 2:  # File creation time changed
            self._process_file_time_event(event)
        elif event_id == 3:  # Network connection
            self._process_network_event(event)
        elif event_id == 5:  # Process terminated
            self._process_process_terminated(event)
        elif event_id == 7:  # Image loaded
            self._process_image_load_event(event)
        elif event_id == 8:  # CreateRemoteThread
            self._process_remote_thread(event)
        elif event_id == 10:  # ProcessAccess
            self._process_process_access(event)
        elif event_id == 11:  # FileCreate
            self._process_file_event(event)
        elif event_id == 12:  # Registry object add/delete
            self._process_registry_event(event)
        elif event_id == 13:  # Registry value set
            self._process_registry_event(event)
        elif event_id == 14:  # Registry object renamed
            self._process_registry_event(event)
        elif event_id == 15:  # FileCreateStreamHash
            self._process_alternate_data_stream(event)
        elif event_id == 17:  # PipeEvent (Pipe Created)
            self._process_pipe_event(event)
        elif event_id == 18:  # PipeEvent (Pipe Connected)
            self._process_pipe_event(event)
        elif event_id == 22:  # DNS query
            self._process_dns_event(event)
        elif event_id == 23:  # FileDelete
            self._process_file_delete(event)
        elif event_id == 24:  # ClipboardChange
            self._process_clipboard_event(event)
        elif event_id == 25:  # ProcessTampering
            self._process_tampering_event(event)

    def on_wmi_event(self, event: Dict) -> None:
        """Обработка события от WMI"""
        event_class = event.get('class', '')

        if 'ProcessStart' in event_class:
            self._process_wmi_process_start(event)
        elif 'ProcessStop' in event_class:
            self._process_wmi_process_stop(event)
        elif 'Service' in event_class:
            self._process_wmi_service_change(event)
        elif 'Registry' in event_class:
            self._process_registry_event(event)

    def _windows_event_loop(self) -> None:
        """Цикл чтения Windows Event Log (с пакетной обработкой)"""
        import win32evtlog
        import win32evtlogutil
        import pywintypes

        # Открываем все настроенные логи
        for log_name in self.win_event_logs:
            try:
                handle = win32evtlog.OpenEventLog(None, log_name)
                self.event_log_handles[log_name] = handle
                total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
                self.last_event_ids[log_name] = total_records
                self.logger.info(f"Открыт журнал: {log_name} (записей: {total_records})")
            except pywintypes.error as e:
                if e.winerror == 2:
                    self.logger.debug(f"Журнал {log_name} не найден")
            except Exception as e:
                self.logger.debug(f"Не удалось открыть журнал {log_name}: {e}")

        # Буфер для пакетной обработки
        event_buffer = []
        buffer_size = 100
        last_flush = time.time()
        flush_interval = 1  # секунда

        while self.running:
            for log_name, handle in list(self.event_log_handles.items()):
                try:
                    events_read = self._read_new_events_batch(log_name, handle, max_events=50)

                    if events_read:
                        event_buffer.extend(events_read)

                        # Пакетная публикация
                        if len(event_buffer) >= buffer_size or time.time() - last_flush > flush_interval:
                            for event in event_buffer:
                                if 'sysmon' in event.get('log_name', '').lower():
                                    self.event_bus.publish('sysmon.event', event)
                                else:
                                    self.event_bus.publish('edr.event', event)
                            event_buffer.clear()
                            last_flush = time.time()

                except pywintypes.error as e:
                    if e.winerror == 6:
                        try:
                            win32evtlog.CloseEventLog(handle)
                        except:
                            pass
                        try:
                            self.event_log_handles[log_name] = win32evtlog.OpenEventLog(None, log_name)
                        except:
                            del self.event_log_handles[log_name]
                except Exception as e:
                    self.logger.debug(f"Ошибка чтения журнала {log_name}: {e}")

            time.sleep(0.1)  # Небольшая пауза чтобы не нагружать CPU

    def _read_new_events_batch(self, log_name: str, handle, max_events: int = 50) -> List[Dict]:
        """Пакетное чтение новых событий"""
        import win32evtlog

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []

        try:
            for _ in range(max_events):
                try:
                    raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not raw_events:
                        break

                    for event in raw_events:
                        parsed = self._parse_windows_event(log_name, event)
                        if parsed:
                            events.append(parsed)

                except Exception:
                    break
        except Exception as e:
            self.logger.debug(f"Ошибка пакетного чтения: {e}")

        return events


    def _parse_windows_event(self, log_name: str, event) -> Optional[Dict]:
        """Парсинг Windows Event в унифицированный формат"""
        import win32evtlogutil

        try:
            # Извлекаем основную информацию
            event_id = event.EventID & 0xFFFF
            event_category = event.EventCategory
            time_generated = event.TimeGenerated
            time_written = event.TimeWritten
            computer_name = event.ComputerName
            source_name = event.SourceName
            record_number = event.RecordNumber

            # Пытаемся получить сообщение
            try:
                message = win32evtlogutil.SafeFormatMessage(event, log_name)
            except:
                message = ''

            # Базовый результат
            result = {
                'event_id': event_id,
                'log_name': log_name,
                'source': source_name,
                'computer': computer_name,
                'record_number': record_number,
                'time_generated': time_generated.isoformat() if time_generated else None,
                'time_written': time_written.isoformat() if time_written else None,
                'timestamp': time.time(),
                'category': event_category,
                'message': message[:2000] if message else '',
                'raw_inserts': list(event.StringInserts) if event.StringInserts else []
            }

            # Парсинг специфичных событий
            if log_name == 'Security':
                self._parse_security_event(event_id, result)
            elif 'Sysmon' in log_name:
                self._parse_sysmon_event(event_id, result)
            elif 'PowerShell' in log_name:
                self._parse_powershell_event(event_id, result)
            elif 'WMI' in log_name:
                self._parse_wmi_log_event(event_id, result)
            elif 'TaskScheduler' in log_name:
                self._parse_task_scheduler_event(event_id, result)
            elif 'TerminalServices' in log_name:
                self._parse_rdp_event(event_id, result)

            return result

        except Exception as e:
            self.logger.debug(f"Ошибка парсинга события: {e}")
            return None

    def _parse_security_event(self, event_id: int, result: Dict) -> None:
        """Парсинг Security событий"""
        message = result.get('message', '')
        inserts = result.get('raw_inserts', [])

        # 4624 - Успешный вход
        if event_id == 4624:
            result['event_type'] = 'login'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['domain'] = self._extract_from_message(message, r'Account Domain:\s+([^\r\n]+)')
            result['logon_type'] = self._extract_from_message(message, r'Logon Type:\s+(\d+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Network Address:\s+([^\r\n]+)')
            result['src_port'] = self._extract_from_message(message, r'Source Port:\s+(\d+)')
            result['process_name'] = self._extract_from_message(message, r'Process Name:\s+([^\r\n]+)')
            result['logon_id'] = self._extract_from_message(message, r'Logon ID:\s+([^\r\n]+)')

            # Тип входа
            logon_types = {
                '2': 'Interactive',
                '3': 'Network',
                '4': 'Batch',
                '5': 'Service',
                '7': 'Unlock',
                '8': 'NetworkCleartext',
                '9': 'NewCredentials',
                '10': 'RemoteInteractive',
                '11': 'CachedInteractive'
            }
            result['logon_type_name'] = logon_types.get(result.get('logon_type', ''), 'Unknown')

            # Специальные проверки
            if result.get('logon_type') == '10':  # RDP
                result['is_remote'] = True
            if result.get('logon_type') == '3' and not result.get('src_ip'):
                result['is_local_network'] = True

        # 4625 - Неудачный вход
        elif event_id == 4625:
            result['event_type'] = 'failed_login'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['domain'] = self._extract_from_message(message, r'Account Domain:\s+([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Network Address:\s+([^\r\n]+)')
            result['failure_reason'] = self._extract_from_message(message, r'Failure Reason:\s+([^\r\n]+)')
            result['status'] = self._extract_from_message(message, r'Status:\s+([^\r\n]+)')
            result['sub_status'] = self._extract_from_message(message, r'Sub Status:\s+([^\r\n]+)')

            # Расшифровка статуса
            status_codes = {
                '0xC0000064': 'User does not exist',
                '0xC000006A': 'Wrong password',
                '0xC0000234': 'Account locked',
                '0xC0000072': 'Account disabled',
                '0xC000006F': 'User not allowed',
                '0xC0000070': 'Invalid workstation',
                '0xC0000071': 'Password expired',
                '0xC0000133': 'Clocks out of sync',
                '0xC000015B': 'User not granted logon right',
                '0xC0000193': 'Account expired'
            }
            status = result.get('status', '').upper()
            result['status_description'] = status_codes.get(status, status)

        # 4688 - Создание процесса
        elif event_id == 4688:
            result['event_type'] = 'process'
            result['process_name'] = self._extract_from_message(message, r'New Process Name:\s+([^\r\n]+)')
            result['command_line'] = self._extract_from_message(message, r'Process Command Line:\s+([^\r\n]+)')
            result['creator_process'] = self._extract_from_message(message, r'Creator Process Name:\s+([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'New Process ID:\s+([^\r\n]+)')
            result['creator_process_id'] = self._extract_from_message(message, r'Creator Process ID:\s+([^\r\n]+)')
            result['token_elevation'] = self._extract_from_message(message, r'Token Elevation Type:\s+([^\r\n]+)')
            result['mandatory_label'] = self._extract_from_message(message, r'Mandatory Label:\s+([^\r\n]+)')

            # Извлекаем username из строки Subject
            subject_match = re.search(r'Subject:.*?Account Name:\s+([^\r\n]+)', message, re.DOTALL)
            if subject_match:
                result['username'] = subject_match.group(1).strip()

        # 4689 - Завершение процесса
        elif event_id == 4689:
            result['event_type'] = 'process_terminated'
            result['process_name'] = self._extract_from_message(message, r'Process Name:\s+([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'Process ID:\s+([^\r\n]+)')
            result['exit_status'] = self._extract_from_message(message, r'Exit Status:\s+([^\r\n]+)')

        # 5140 - Доступ к сетевой папке
        elif event_id == 5140:
            result['event_type'] = 'file_share'
            result['share_name'] = self._extract_from_message(message, r'Share Name:\s*([^\r\n]+)')
            result['share_path'] = self._extract_from_message(message, r'Share Path:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Address:\s*([^\r\n]+)')
            result['username'] = self._extract_from_message(message, r'Account Name:\s*([^\r\n]+)')
            result['accesses'] = self._extract_from_message(message, r'Accesses:\s*([^\r\n]+)')

        # 5145 - Доступ к файлу по сети
        elif event_id == 5145:
            result['event_type'] = 'file_access'
            result['file_name'] = self._extract_from_message(message, r'Relative Target Name:\s*([^\r\n]+)')
            result['share_name'] = self._extract_from_message(message, r'Share Name:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Address:\s*([^\r\n]+)')
            result['username'] = self._extract_from_message(message, r'Account Name:\s*([^\r\n]+)')
            result['access_mask'] = self._extract_from_message(message, r'Access Mask:\s*([^\r\n]+)')

        # 5156 - Фильтрация платформы Windows (сетевое соединение)
        elif event_id == 5156:
            result['event_type'] = 'network'
            result['process_name'] = self._extract_from_message(message, r'Application Name:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Address:\s*([^\r\n]+)')
            result['dst_ip'] = self._extract_from_message(message, r'Dest Address:\s*([^\r\n]+)')
            result['src_port'] = self._extract_from_message(message, r'Source Port:\s*(\d+)')
            result['dst_port'] = self._extract_from_message(message, r'Dest Port:\s*(\d+)')
            result['protocol'] = self._extract_from_message(message, r'Protocol:\s*(\d+)')
            result['direction'] = self._extract_from_message(message, r'Direction:\s*([^\r\n]+)')

        # 5158 - Bind to local port
        elif event_id == 5158:
            result['event_type'] = 'network_bind'
            result['process_name'] = self._extract_from_message(message, r'Application Name:\s*([^\r\n]+)')
            result['local_port'] = self._extract_from_message(message, r'Local Port:\s*(\d+)')
            result['protocol'] = self._extract_from_message(message, r'Protocol:\s*(\d+)')

        # 1102 - Очистка журнала аудита
        elif event_id == 1102:
            result['event_type'] = 'audit_log_cleared'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['domain'] = self._extract_from_message(message, r'Domain Name:\s+([^\r\n]+)')

        # 4672 - Назначение специальных привилегий
        elif event_id == 4672:
            result['event_type'] = 'special_privileges'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['privileges'] = self._extract_from_message(message, r'Privileges:\s+([^\r\n]+)')

        # 4720 - Создание пользователя
        elif event_id == 4720:
            result['event_type'] = 'user_created'
            result['new_username'] = self._extract_from_message(message, r'SAM Account Name:\s+([^\r\n]+)')
            result['creator'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')

        # 4732 - Добавление в группу
        elif event_id == 4732:
            result['event_type'] = 'group_member_added'
            result['username'] = self._extract_from_message(message, r'Member Name:\s+([^\r\n]+)')
            result['group_name'] = self._extract_from_message(message, r'Group Name:\s+([^\r\n]+)')

    def _parse_sysmon_event(self, event_id: int, result: Dict) -> None:
        """Парсинг Sysmon событий"""
        message = result.get('message', '')

        # Event ID 1 - Process Creation
        if event_id == 1:
            result['event_type'] = 'process'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['command_line'] = self._extract_from_message(message, r'CommandLine:\s*([^\r\n]+)')
            result['parent_process'] = self._extract_from_message(message, r'ParentImage:\s*([^\r\n]+)')
            result['parent_command_line'] = self._extract_from_message(message, r'ParentCommandLine:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['pid'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['parent_pid'] = self._extract_from_message(message, r'ParentProcessId:\s*(\d+)')
            result['file_hash'] = self._extract_from_message(message, r'Hashes:\s*([^\r\n]+)')
            result['current_directory'] = self._extract_from_message(message, r'CurrentDirectory:\s*([^\r\n]+)')
            result['integrity_level'] = self._extract_from_message(message, r'IntegrityLevel:\s*([^\r\n]+)')

        # Event ID 3 - Network Connection
        elif event_id == 3:
            result['event_type'] = 'network'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'SourceIp:\s*([^\r\n]+)')
            result['dst_ip'] = self._extract_from_message(message, r'DestinationIp:\s*([^\r\n]+)')
            result['src_port'] = self._extract_from_message(message, r'SourcePort:\s*(\d+)')
            result['dst_port'] = self._extract_from_message(message, r'DestinationPort:\s*(\d+)')
            result['protocol'] = self._extract_from_message(message, r'Protocol:\s*([^\r\n]+)')
            result['initiated'] = self._extract_from_message(message, r'Initiated:\s*([^\r\n]+)')

        # Event ID 7 - Image Loaded
        elif event_id == 7:
            result['event_type'] = 'image_load'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['image_loaded'] = self._extract_from_message(message, r'ImageLoaded:\s*([^\r\n]+)')
            result['file_hash'] = self._extract_from_message(message, r'Hashes:\s*([^\r\n]+)')
            result['signed'] = self._extract_from_message(message, r'Signed:\s*([^\r\n]+)')
            result['signature'] = self._extract_from_message(message, r'Signature:\s*([^\r\n]+)')

        # Event ID 8 - CreateRemoteThread
        elif event_id == 8:
            result['event_type'] = 'remote_thread'
            result['source_process'] = self._extract_from_message(message, r'SourceImage:\s*([^\r\n]+)')
            result['target_process'] = self._extract_from_message(message, r'TargetImage:\s*([^\r\n]+)')
            result['source_pid'] = self._extract_from_message(message, r'SourceProcessId:\s*(\d+)')
            result['target_pid'] = self._extract_from_message(message, r'TargetProcessId:\s*(\d+)')
            result['start_address'] = self._extract_from_message(message, r'StartAddress:\s*([^\r\n]+)')
            result['start_function'] = self._extract_from_message(message, r'StartFunction:\s*([^\r\n]+)')

        # Event ID 10 - ProcessAccess
        elif event_id == 10:
            result['event_type'] = 'process_access'
            result['source_process'] = self._extract_from_message(message, r'SourceImage:\s*([^\r\n]+)')
            result['target_process'] = self._extract_from_message(message, r'TargetImage:\s*([^\r\n]+)')
            result['granted_access'] = self._extract_from_message(message, r'GrantedAccess:\s*([^\r\n]+)')
            result['call_trace'] = self._extract_from_message(message, r'CallTrace:\s*([^\r\n]+)')

            # Проверка опасных доступов
            dangerous_access = ['0x1FFFFF', '0x1F0FFF', 'PROCESS_ALL_ACCESS', 'PROCESS_CREATE_THREAD',
                                'PROCESS_VM_WRITE', 'PROCESS_VM_OPERATION']
            for da in dangerous_access:
                if da in result.get('granted_access', ''):
                    result['dangerous_access'] = True
                    break

        # Event ID 11 - FileCreate
        elif event_id == 11:
            result['event_type'] = 'file'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['filename'] = self._extract_from_message(message, r'TargetFilename:\s*([^\r\n]+)')
            result['creation_time'] = self._extract_from_message(message, r'CreationUtcTime:\s*([^\r\n]+)')

        # Event ID 12/13/14 - Registry
        elif event_id in [12, 13, 14]:
            result['event_type'] = 'registry'
            result['event_subtype'] = {12: 'create_delete', 13: 'set', 14: 'rename'}.get(event_id, 'unknown')
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['key_path'] = self._extract_from_message(message, r'TargetObject:\s*([^\r\n]+)')
            result['value_name'] = self._extract_from_message(message, r'Details:\s*([^\r\n]+)')

        # Event ID 22 - DNS Query
        elif event_id == 22:
            result['event_type'] = 'dns'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['query_name'] = self._extract_from_message(message, r'QueryName:\s*([^\r\n]+)')
            result['query_status'] = self._extract_from_message(message, r'QueryStatus:\s*([^\r\n]+)')
            result['query_results'] = self._extract_from_message(message, r'QueryResults:\s*([^\r\n]+)')

        # Event ID 25 - ProcessTampering
        elif event_id == 25:
            result['event_type'] = 'process_tampering'
            result['process_name'] = self._extract_from_message(message, r'ProcessName:\s*([^\r\n]+)')
            result['technique'] = self._extract_from_message(message, r'Type:\s*([^\r\n]+)')

    def _parse_powershell_event(self, event_id: int, result: Dict) -> None:
        """Парсинг PowerShell событий"""
        message = result.get('message', '')

        result['event_type'] = 'powershell'

        # Event ID 4103 - Module Logging
        if event_id == 4103:
            result['subtype'] = 'module'
            result['user'] = self._extract_from_message(message, r'UserId=([^\r\n]+)')
            result['host'] = self._extract_from_message(message, r'Host Name=([^\r\n]+)')
            result['command'] = self._extract_from_message(message, r'CommandInvocation\([^\)]*\):\s*([^\r\n]+)')
            result['parameter_binding'] = self._extract_from_message(message, r'ParameterBinding\([^\)]*\):\s*([^\r\n]+)')

        # Event ID 4104 - Script Block Logging
        elif event_id == 4104:
            result['subtype'] = 'script_block'
            result['script_block_id'] = self._extract_from_message(message, r'ScriptBlock ID:\s*([^\r\n]+)')

            # Извлекаем сам скрипт
            script_match = re.search(r'ScriptBlock text:\s*\n(.*?)(?:\n\s*\n|$)', message, re.DOTALL)
            if script_match:
                result['script_block'] = script_match.group(1).strip()[:5000]

        # Event ID 800 - Pipeline Execution Details
        elif event_id == 800:
            result['subtype'] = 'pipeline'
            result['user'] = self._extract_from_message(message, r'UserId=([^\r\n]+)')
            result['host'] = self._extract_from_message(message, r'HostName=([^\r\n]+)')
            result['command_line'] = self._extract_from_message(message, r'CommandLine=([^\r\n]+)')

    def _parse_wmi_log_event(self, event_id: int, result: Dict) -> None:
        """Парсинг WMI событий из лога"""
        message = result.get('message', '')

        result['event_type'] = 'wmi'

        # Event ID 5858 - WMI Activity
        if event_id == 5858:
            result['operation'] = self._extract_from_message(message, r'Operation:\s*([^\r\n]+)')
            result['namespace'] = self._extract_from_message(message, r'Namespace:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['query'] = self._extract_from_message(message, r'Query:\s*([^\r\n]+)')

        # Event ID 5861 - WMI Permanent Event Registration
        elif event_id == 5861:
            result['subtype'] = 'permanent_event'
            result['filter'] = self._extract_from_message(message, r'Filter:\s*([^\r\n]+)')
            result['consumer'] = self._extract_from_message(message, r'Consumer:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')

    def _parse_task_scheduler_event(self, event_id: int, result: Dict) -> None:
        """Парсинг Task Scheduler событий"""
        message = result.get('message', '')

        result['event_type'] = 'task_scheduler'

        # Event ID 106 - Task Registered
        if event_id == 106:
            result['subtype'] = 'task_registered'
            result['task_name'] = self._extract_from_message(message, r'Task Name:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User Name:\s*([^\r\n]+)')

        # Event ID 141 - Task Updated
        elif event_id == 141:
            result['subtype'] = 'task_updated'
            result['task_name'] = self._extract_from_message(message, r'Task Name:\s*([^\r\n]+)')

        # Event ID 200/201 - Task Executed
        elif event_id in [200, 201]:
            result['subtype'] = 'task_executed'
            result['task_name'] = self._extract_from_message(message, r'Task Name:\s*([^\r\n]+)')
            result['action'] = self._extract_from_message(message, r'Action:\s*([^\r\n]+)')
            result['result_code'] = self._extract_from_message(message, r'Result code:\s*([^\r\n]+)')

    def _parse_rdp_event(self, event_id: int, result: Dict) -> None:
        """Парсинг RDP событий"""
        message = result.get('message', '')

        result['event_type'] = 'rdp'

        # Event ID 21 - RDP Session Start
        if event_id == 21:
            result['subtype'] = 'session_start'
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Network Address:\s*([^\r\n]+)')

        # Event ID 24 - RDP Session Disconnect
        elif event_id == 24:
            result['subtype'] = 'session_disconnect'
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['session_id'] = self._extract_from_message(message, r'Session ID:\s*(\d+)')

    def _extract_from_message(self, message: str, pattern: str) -> Optional[str]:
        """Извлечение значения из сообщения по регулярному выражению"""
        import re
        match = re.search(pattern, message, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    def _wmi_event_loop(self) -> None:
        """Цикл мониторинга WMI событий"""
        if not self.use_wmi or not self.wmi_connection:
            return

        try:
            import pythoncom

            pythoncom.CoInitialize()

            # Мониторинг создания процессов
            process_watcher = self._create_wmi_watcher(
                "SELECT * FROM Win32_ProcessStartTrace",
                self._handle_wmi_process_start
            )
            if process_watcher:
                self.wmi_watchers.append(process_watcher)

            # Мониторинг завершения процессов
            process_stop_watcher = self._create_wmi_watcher(
                "SELECT * FROM Win32_ProcessStopTrace",
                self._handle_wmi_process_stop
            )
            if process_stop_watcher:
                self.wmi_watchers.append(process_stop_watcher)

            # Мониторинг изменений сервисов
            service_watcher = self._create_wmi_watcher(
                "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service'",
                self._handle_wmi_service_change
            )
            if service_watcher:
                self.wmi_watchers.append(service_watcher)

            # Мониторинг изменений реестра
            registry_watcher = self._create_wmi_watcher(
                "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'",
                self._handle_wmi_registry_change
            )
            if service_watcher:
                self.wmi_watchers.append(registry_watcher)

            # Основной цикл ожидания
            while self.running:
                time.sleep(1)

        except Exception as e:
            self.logger.error(f"Ошибка WMI мониторинга: {e}")
        finally:
            try:
                import pythoncom
                pythoncom.CoUninitialize()
            except:
                pass

    def _create_wmi_watcher(self, query: str, handler: Callable):
        """Создание WMI вотчера"""
        try:
            import wmi

            watcher = wmi.WMI().watch_for(
                notification_type="Operation",
                wmi_class=None,
                wmi_query=query
            )
            threading.Thread(target=self._wmi_watcher_loop, args=(watcher, handler), daemon=True).start()
            return watcher
        except Exception as e:
            self.logger.debug(f"Ошибка создания WMI вотчера: {e}")
            return None

    def _wmi_watcher_loop(self, watcher, handler) -> None:
        """Цикл обработки WMI событий"""
        while self.running:
            try:
                event = watcher(timeout_ms=1000)
                if event:
                    handler(event)
            except Exception as e:
                if self.running:
                    self.logger.debug(f"Ошибка WMI вотчера: {e}")

    def _handle_wmi_process_start(self, event) -> None:
        """Обработка WMI события создания процесса"""
        parsed = {
            'event_type': 'process',
            'source': 'wmi',
            'process_name': getattr(event, 'ProcessName', ''),
            'process_id': getattr(event, 'ProcessID', 0),
            'parent_process_id': getattr(event, 'ParentProcessID', 0),
            'command_line': getattr(event, 'CommandLine', ''),
            'timestamp': time.time()
        }
        self.event_bus.publish('wmi.event', parsed)

    def _handle_wmi_process_stop(self, event) -> None:
        """Обработка WMI события завершения процесса"""
        parsed = {
            'event_type': 'process_terminated',
            'source': 'wmi',
            'process_name': getattr(event, 'ProcessName', ''),
            'process_id': getattr(event, 'ProcessID', 0),
            'exit_status': getattr(event, 'ExitStatus', 0),
            'timestamp': time.time()
        }
        self.event_bus.publish('wmi.event', parsed)

    def _handle_wmi_service_change(self, event) -> None:
        """Обработка WMI события изменения сервиса"""
        target = getattr(event, 'TargetInstance', None)
        if target:
            parsed = {
                'event_type': 'service',
                'source': 'wmi',
                'service_name': getattr(target, 'Name', ''),
                'display_name': getattr(target, 'DisplayName', ''),
                'state': getattr(target, 'State', ''),
                'start_mode': getattr(target, 'StartMode', ''),
                'path_name': getattr(target, 'PathName', ''),
                'start_name': getattr(target, 'StartName', ''),
                'timestamp': time.time()
            }
            self.event_bus.publish('wmi.event', parsed)

    def _handle_wmi_registry_change(self, event) -> None:
        """Обработка WMI события изменения реестра"""
        parsed = {
            'event_type': 'registry',
            'source': 'wmi',
            'key_path': getattr(event, 'KeyPath', ''),
            'timestamp': time.time()
        }
        self.event_bus.publish('wmi.event', parsed)

    def _process_process_event(self, event: Dict) -> None:
        """Анализ события создания процесса"""
        self.process_events.append(event)

        result = self.analyze_process_event(event)

        if result['is_suspicious']:
            self.event_bus.publish('edr.threat', result)
            self.logger.warning(f"Подозрительный процесс: {event.get('process_name')} (score={result['score']:.3f})")

    def analyze_process_event(self, event: Dict) -> Dict:
        """Анализ события процесса"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'attack_type': None,
            'severity': AlertSeverity.LOW.value
        }

        process_name = event.get('process_name', '').lower()
        cmdline = event.get('command_line', '').lower()
        path = event.get('path', event.get('process_name', '')).lower()
        parent_process = event.get('parent_process', '').lower()
        user = event.get('user', '').lower()
        pid = event.get('pid', event.get('process_id', 0))

        # 1. Подозрительный процесс
        for sus_proc in self.suspicious_processes:
            if sus_proc in process_name:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_process:{sus_proc}")
                result['score'] += 0.25

                # Особо опасные процессы
                if sus_proc in ['mimikatz.exe', 'procdump.exe', 'psexec.exe']:
                    result['score'] += 0.3
                    result['attack_type'] = 'Credential Dumping'
                elif sus_proc in ['powershell.exe', 'cmd.exe']:
                    result['score'] += 0.1
                break

        # 2. Подозрительные аргументы командной строки
        for pattern in self.suspicious_cmdline:
            if pattern in cmdline:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_cmdline:{pattern}")
                result['score'] += 0.3

                if pattern in ['mimikatz', 'procdump', 'lsass', 'sekurlsa']:
                    result['attack_type'] = 'Credential Dumping'
                    result['score'] += 0.2
                elif pattern in ['cobaltstrike', 'metasploit', 'meterpreter']:
                    result['attack_type'] = 'C2 Framework'
                    result['score'] += 0.25
                elif pattern in ['virtualalloc', 'createremotethread', 'writeprocessmemory']:
                    result['attack_type'] = 'Process Injection'
                    result['score'] += 0.2
                break

        # 3. Процесс запущен из подозрительной папки
        for sus_path in self.suspicious_paths:
            if sus_path in path:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_path:{sus_path}")
                result['score'] += 0.25
                break

        # 4. Необычный родительский процесс
        suspicious_parents = {
            'powershell.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe', 'mshta.exe'],
            'cmd.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'java.exe', 'javaw.exe', 'mshta.exe'],
            'wscript.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'mshta.exe'],
            'rundll32.exe': ['winword.exe', 'excel.exe', 'outlook.exe'],
            'mshta.exe': ['winword.exe', 'excel.exe', 'outlook.exe'],
            'regsvr32.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'mshta.exe']
        }

        for proc_name, sus_parents in suspicious_parents.items():
            if proc_name in process_name:
                for sus_parent in sus_parents:
                    if sus_parent in parent_process:
                        result['is_suspicious'] = True
                        result['reasons'].append(f"suspicious_parent:{parent_process}->{proc_name}")
                        result['score'] += 0.35
                        result['attack_type'] = 'Office Macro'
                        break
                break

        # 5. PowerShell с подозрительными флагами
        if 'powershell' in process_name:
            dangerous_flags = [
                ('-windowstyle hidden', 0.3),
                ('-w hidden', 0.3),
                ('-executionpolicy bypass', 0.25),
                ('-ep bypass', 0.25),
                ('-enc ', 0.35),
                ('-encodedcommand ', 0.35),
                ('-nop', 0.1),
                ('-noprofile', 0.1),
                ('invoke-expression', 0.3),
                ('iex ', 0.3),
                ('downloadstring', 0.3),
                ('downloadfile', 0.25),
                ('frombase64string', 0.2),
                ('[system.reflection.assembly]::load', 0.4),
                ('add-type -typedefinition', 0.3)
            ]

            for flag, score_add in dangerous_flags:
                if flag in cmdline:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"powershell_{flag.replace(' ', '_')}")
                    result['score'] += score_add
                    if score_add >= 0.3:
                        break

        # 6. WMI с подозрительными командами
        if 'wmic' in process_name or 'wmi' in cmdline:
            dangerous_wmi = ['process call create', 'service call create', 'shadowcopy delete',
                             '/node:', 'useraccount', 'startup', 'os get']
            for wmi_cmd in dangerous_wmi:
                if wmi_cmd in cmdline:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"suspicious_wmi:{wmi_cmd}")
                    result['score'] += 0.3
                    break

        # 7. Доступ к LSASS
        if 'lsass' in cmdline:
            result['is_suspicious'] = True
            result['reasons'].append("lsass_access")
            result['score'] += 0.4
            result['attack_type'] = 'Credential Dumping'

        # 8. Запуск из ADS (Alternate Data Stream)
        if ':Zone.Identifier' in path or ':$DATA' in path:
            result['is_suspicious'] = True
            result['reasons'].append("ads_execution")
            result['score'] += 0.35

        # 9. Неподписанный процесс из системной папки
        if 'system32' in path and event.get('signed') == 'false':
            result['is_suspicious'] = True
            result['reasons'].append("unsigned_system32_binary")
            result['score'] += 0.25

        # 10. Подозрительный пользователь
        suspicious_users = ['system', 'local service', 'network service']
        if user.lower() in suspicious_users and 'cmd.exe' in process_name:
            result['is_suspicious'] = True
            result['reasons'].append(f"system_account_cmd:{user}")
            result['score'] += 0.2

        result['score'] = min(1.0, result['score'])

        # Определение серьёзности
        if result['score'] > 0.7:
            result['severity'] = AlertSeverity.CRITICAL.value
        elif result['score'] > 0.5:
            result['severity'] = AlertSeverity.HIGH.value
        elif result['score'] > 0.3:
            result['severity'] = AlertSeverity.MEDIUM.value

        if not result['attack_type']:
            result['attack_type'] = 'Suspicious Process'

        result['details'] = {
            'process_name': process_name,
            'command_line': cmdline[:500],
            'path': path,
            'parent_process': parent_process,
            'user': user,
            'pid': pid
        }

        return result

    def _process_file_event(self, event: Dict) -> None:
        """Анализ файлового события"""
        self.file_events.append(event)

        filename = event.get('filename', '').lower()
        path = event.get('path', '').lower()
        operation = event.get('operation', '')
        process_name = event.get('process_name', '').lower()

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'file'
        }

        # 1. Создание файлов в чувствительных директориях
        sensitive_dirs = [
            '\\system32\\', '\\syswow64\\', '\\windows\\',
            '\\program files\\', '\\program files (x86)\\',
            '\\startup\\', '\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\',
            '\\tasks\\', '\\windows\\system32\\tasks\\'
        ]

        for sens_dir in sensitive_dirs:
            if sens_dir in path and operation in ('create', 'modify', 'write'):
                if 'windows update' not in path and 'microsoft' not in path.lower():
                    result['is_suspicious'] = True
                    result['reasons'].append(f"sensitive_dir_write:{sens_dir}")
                    result['score'] += 0.35
                    break

        # 2. Подозрительные расширения в темповых папках
        dangerous_extensions = ['.exe', '.dll', '.sys', '.ps1', '.vbs', '.js', '.hta', '.bat', '.scr']
        is_temp_path = any(temp in path for temp in ['\\temp\\', '\\tmp\\', '\\cache\\', '\\downloads\\'])

        if is_temp_path:
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"executable_in_temp:{filename}")
                    result['score'] += 0.4
                    break

        # 3. Создание скриптов офисными приложениями
        office_processes = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
        script_extensions = ['.ps1', '.vbs', '.js', '.bat', '.hta']

        if any(proc in process_name for proc in office_processes):
            for ext in script_extensions:
                if filename.endswith(ext):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"office_created_script:{filename}")
                    result['score'] += 0.5
                    result['attack_type'] = 'Office Macro'
                    break

        # 4. Файлы с двойным расширением
        if filename.count('.') >= 2:
            parts = filename.split('.')
            if parts[-1] in dangerous_extensions and parts[-2] in ['doc', 'xls', 'pdf', 'txt', 'jpg']:
                result['is_suspicious'] = True
                result['reasons'].append(f"double_extension:{filename}")
                result['score'] += 0.45

        # 5. Подозрительные имена файлов
        suspicious_names = ['mimikatz', 'procdump', 'psexec', 'nc.exe', 'netcat', 'plink.exe',
                            'socat', 'chisel', 'frpc', 'nps', 'beacon', 'payload', 'shell']
        for sus_name in suspicious_names:
            if sus_name in filename:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_filename:{sus_name}")
                result['score'] += 0.35
                break

        # 6. Изменение системных файлов
        system_files = ['hosts', 'services', 'lmhosts', 'protocol', 'networks']
        for sys_file in system_files:
            if f'\\etc\\{sys_file}' in path or f'\\drivers\\etc\\{sys_file}' in path:
                if operation in ('modify', 'write'):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"system_file_modified:{sys_file}")
                    result['score'] += 0.4
                    break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['filename'] = filename
            result['path'] = path
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.6:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.4:
                result['severity'] = AlertSeverity.MEDIUM.value
            else:
                result['severity'] = AlertSeverity.LOW.value

            self.event_bus.publish('edr.file_threat', result)
            self.logger.warning(f"Подозрительная файловая операция: {filename} (score={result['score']:.3f})")

    def _process_registry_event(self, event: Dict) -> None:
        """Анализ события реестра"""
        self.registry_events.append(event)

        key_path = event.get('key_path', '').lower()
        value_name = event.get('value_name', '').lower()
        operation = event.get('operation', '')
        process_name = event.get('process_name', '').lower()

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'registry'
        }

        # 1. Чувствительные ключи реестра
        for sens_key in self.suspicious_registry_keys:
            if sens_key in key_path:
                if operation in ('set', 'create', 'modify', 'write'):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"sensitive_registry:{sens_key}")
                    result['score'] += 0.35

                    # Persistence механизмы
                    if 'run' in sens_key or 'runonce' in sens_key:
                        result['attack_type'] = 'Persistence'
                        result['score'] += 0.1
                    elif 'winlogon' in sens_key:
                        result['attack_type'] = 'Credential Access'
                        result['score'] += 0.15
                    break

        # 2. Отключение защитных механизмов
        security_disable_patterns = [
            ('disableantispyware', 0.4),
            ('disableantivirus', 0.4),
            ('enablefirewall', 0.35),
            ('disableuac', 0.35),
            ('disablerealtimeMonitoring', 0.4),
            ('disableioavprotection', 0.35),
            ('disablebehaviorMonitoring', 0.35),
            ('disableonaccessprotection', 0.35),
            ('disableintrusionpreventionsystem', 0.35),
            ('disableScriptScanning', 0.3)
        ]

        for pattern, score_add in security_disable_patterns:
            if pattern in value_name or pattern in key_path:
                result['is_suspicious'] = True
                result['reasons'].append(f"security_disable:{pattern}")
                result['score'] += score_add
                break

        # 3. Модификация Image File Execution Options (IFEO)
        if 'image file execution options' in key_path:
            result['is_suspicious'] = True
            result['reasons'].append("ifeo_modification")
            result['score'] += 0.5
            result['attack_type'] = 'Persistence'

            # Проверка на Debugger
            if 'debugger' in value_name:
                result['score'] += 0.2

        # 4. Изменение Shell Extensions
        if 'shell extensions\\approved' in key_path:
            result['is_suspicious'] = True
            result['reasons'].append("shell_extension_approved")
            result['score'] += 0.4
            result['attack_type'] = 'Persistence'

        # 5. Подозрительный процесс изменяет реестр
        if process_name in self.suspicious_processes:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_process_registry:{process_name}")
            result['score'] += 0.25

        # 6. Удаление ключей безопасности
        security_keys = ['policies', 'audit', 'firewall', 'defender', 'antivirus']
        for sec_key in security_keys:
            if sec_key in key_path and operation in ('delete', 'remove'):
                result['is_suspicious'] = True
                result['reasons'].append(f"security_key_deleted:{sec_key}")
                result['score'] += 0.4
                break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['key_path'] = key_path
            result['value_name'] = value_name
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.6:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.4:
                result['severity'] = AlertSeverity.MEDIUM.value
            else:
                result['severity'] = AlertSeverity.LOW.value

            self.event_bus.publish('edr.registry_threat', result)
            self.logger.warning(f"Подозрительное изменение реестра: {key_path} (score={result['score']:.3f})")

    def _process_network_event(self, event: Dict) -> None:
        """Анализ сетевого события"""
        self.network_events.append(event)

        src_ip = event.get('src_ip', '')
        dst_ip = event.get('dst_ip', '')
        dst_port = event.get('dst_port', 0)
        src_port = event.get('src_port', 0)
        process_name = event.get('process_name', '').lower()
        protocol = event.get('protocol', '')

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'network'
        }

        # 1. Подозрительные порты
        suspicious_ports = {
            4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
            3389, 5900, 5800,
            445, 139, 135,
            22, 23, 21,
            1433, 1434, 3306, 5432,
            8080, 8443, 8000, 8888, 9000
        }

        if dst_port in suspicious_ports:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_port:{dst_port}")
            result['score'] += 0.25

            if dst_port in [4444, 5555, 6666, 7777, 1337, 31337]:
                result['attack_type'] = 'C2 Communication'
                result['score'] += 0.15

        # 2. Подозрительный процесс устанавливает соединение
        if process_name in self.suspicious_processes:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_process_network:{process_name}")
            result['score'] += 0.25

            # Особо подозрительные комбинации
            if process_name == 'powershell.exe' and dst_port not in [80, 443, 53]:
                result['score'] += 0.15
            if process_name == 'rundll32.exe' and dst_port not in [53, 80, 443]:
                result['score'] += 0.2

        # 3. Исходящие соединения на нестандартные порты
        standard_ports = {80, 443, 53, 123, 25, 587, 993, 995, 143, 110}
        if dst_port not in standard_ports and dst_port > 1024:
            if process_name in ['svchost.exe', 'lsass.exe', 'winlogon.exe']:
                result['is_suspicious'] = True
                result['reasons'].append(f"system_process_unusual_port:{process_name}:{dst_port}")
                result['score'] += 0.3

        # 4. Соединения с внутренними IP от необычных процессов
        if self._is_private_ip(dst_ip):
            unusual_internal = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']
            for unusual_proc in unusual_internal:
                if unusual_proc in process_name:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"unusual_internal_connection:{process_name}")
                    result['score'] += 0.25
                    result['attack_type'] = 'Lateral Movement'
                    break

        # 5. Raw socket или необычный протокол
        if protocol and protocol.lower() not in ['tcp', 'udp', 'icmp']:
            result['is_suspicious'] = True
            result['reasons'].append(f"unusual_protocol:{protocol}")
            result['score'] += 0.3

        # 6. Beaconing детекция (на основе таймингов)
        # Реализуется через анализ временных интервалов в _analysis_loop

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['src_ip'] = src_ip
            result['dst_ip'] = dst_ip
            result['dst_port'] = dst_port
            result['src_port'] = src_port
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.6:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.4:
                result['severity'] = AlertSeverity.MEDIUM.value
            else:
                result['severity'] = AlertSeverity.LOW.value

            self.event_bus.publish('edr.network_threat', result)

    def _is_private_ip(self, ip: str) -> bool:
        """Проверка приватного IP"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1]) if len(parts) > 1 else 0
            return (first == 10 or
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168) or
                    first == 127)
        except:
            return False

    def _process_dns_event(self, event: Dict) -> None:
        """Анализ DNS события"""
        self.dns_events.append(event)

        query = event.get('query_name', event.get('query', '')).lower()
        process_name = event.get('process_name', '').lower()
        query_status = event.get('query_status', '')

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'dns'
        }

        # 1. Подозрительный процесс делает DNS запрос
        if process_name in self.suspicious_processes:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_process_dns:{process_name}")
            result['score'] += 0.2

        # 2. Длинные DNS запросы (туннелирование)
        if len(query) > 50:
            result['is_suspicious'] = True
            result['reasons'].append(f"long_dns_query:{len(query)}")
            result['score'] += 0.3
            result['attack_type'] = 'DNS Tunneling'

            if len(query) > 100:
                result['score'] += 0.2

        # 3. Подозрительные TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date']
        for tld in suspicious_tlds:
            if query.endswith(tld):
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_tld:{tld}")
                result['score'] += 0.25
                break

        # 4. DNS over HTTPS признаки
        doh_servers = ['cloudflare-dns.com', 'dns.google', 'dns.quad9.net', 'doh.opendns.com']
        for doh in doh_servers:
            if doh in query:
                if process_name not in ['chrome.exe', 'firefox.exe', 'msedge.exe']:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"unusual_doh:{process_name}")
                    result['score'] += 0.3
                    break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['query'] = query
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.5:
                result['severity'] = AlertSeverity.MEDIUM.value

            self.event_bus.publish('edr.dns_threat', result)
            # Также публикуем для DNS анализатора
            self.event_bus.publish('dpi.dns', {
                'src_ip': event.get('src_ip', ''),
                'query': query,
                'process_name': process_name
            })

    def _process_remote_thread(self, event: Dict) -> None:
        """Анализ создания удалённого потока (Process Injection)"""
        result = {
            'is_suspicious': True,
            'reasons': ['remote_thread_creation'],
            'score': 0.5,
            'attack_type': 'Process Injection',
            'severity': AlertSeverity.HIGH.value,
            'event_type': 'remote_thread'
        }

        result['source_pid'] = event.get('source_pid')
        result['target_pid'] = event.get('target_pid')
        result['source_process'] = event.get('source_process')
        result['target_process'] = event.get('target_process')

        # Проверка целевого процесса
        target = event.get('target_process', '').lower()
        sensitive_targets = ['lsass.exe', 'csrss.exe', 'winlogon.exe', 'explorer.exe', 'svchost.exe']

        for sens_target in sensitive_targets:
            if sens_target in target:
                result['score'] += 0.25
                result['reasons'].append(f"sensitive_target:{sens_target}")
                if sens_target == 'lsass.exe':
                    result['attack_type'] = 'Credential Dumping'
                break

        result['score'] = min(1.0, result['score'])

        self.event_bus.publish('edr.threat', result)
        self.logger.warning(f"Обнаружено создание удалённого потока: {result['source_process']} -> {result['target_process']}")

    def _process_process_access(self, event: Dict) -> None:
        """Анализ доступа к процессу"""
        target_process = event.get('target_process', '').lower()
        source_process = event.get('source_process', '').lower()
        granted_access = event.get('granted_access', '')

        # Доступ к LSASS
        if 'lsass' in target_process:
            result = {
                'is_suspicious': True,
                'reasons': ['lsass_access'],
                'score': 0.6,
                'attack_type': 'Credential Dumping',
                'severity': AlertSeverity.HIGH.value,
                'event_type': 'process_access'
            }

            result['source_process'] = source_process
            result['target_process'] = target_process
            result['granted_access'] = granted_access

            # Проверка опасных прав доступа
            dangerous_rights = ['0x1FFFFF', 'PROCESS_ALL_ACCESS', 'PROCESS_VM_READ', 'PROCESS_QUERY_INFORMATION']
            for right in dangerous_rights:
                if right in granted_access:
                    result['score'] += 0.15
                    result['reasons'].append(f"dangerous_access:{right}")
                    break

            result['score'] = min(1.0, result['score'])

            self.event_bus.publish('edr.threat', result)
            self.logger.warning(f"Обнаружен доступ к LSASS от {source_process}")

    def _process_image_load_event(self, event: Dict) -> None:
        """Анализ загрузки образа (DLL)"""
        self.image_load_events.append(event)

        image_loaded = event.get('image_loaded', '').lower()
        process_name = event.get('process_name', '').lower()
        signed = event.get('signed', '').lower()

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'image_load'
        }

        # 1. Загрузка неподписанной DLL в системный процесс
        system_processes = ['lsass.exe', 'csrss.exe', 'winlogon.exe', 'svchost.exe', 'services.exe']
        if any(proc in process_name for proc in system_processes):
            if signed == 'false':
                result['is_suspicious'] = True
                result['reasons'].append(f"unsigned_dll_in_system_process:{image_loaded}")
                result['score'] += 0.4
                result['attack_type'] = 'DLL Hijacking'

        # 2. Загрузка из подозрительных путей
        for sus_path in self.suspicious_paths:
            if sus_path in image_loaded:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_dll_path:{sus_path}")
                result['score'] += 0.3
                break

        # 3. Подозрительные DLL
        for sus_dll in self.suspicious_dlls:
            if sus_dll in image_loaded:
                # Проверяем контекст
                if 'system32' not in image_loaded:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"suspicious_dll_location:{sus_dll}")
                    result['score'] += 0.35
                    break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['image_loaded'] = image_loaded
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.5:
                result['severity'] = AlertSeverity.MEDIUM.value

            self.event_bus.publish('edr.dll_threat', result)

    def _process_process_terminated(self, event: Dict) -> None:
        """Обработка завершения процесса"""
        # Проверка на необычное завершение защитных процессов
        process_name = event.get('process_name', '').lower()
        security_processes = ['msmpeng.exe', 'windefend.exe', 'msseces.exe', 'avp.exe']

        if any(proc in process_name for proc in security_processes):
            result = {
                'is_suspicious': True,
                'reasons': [f"security_process_terminated:{process_name}"],
                'score': 0.5,
                'attack_type': 'Defense Evasion',
                'severity': AlertSeverity.HIGH.value,
                'event_type': 'process_terminated'
            }
            self.event_bus.publish('edr.threat', result)
            self.logger.warning(f"Завершён процесс безопасности: {process_name}")

    def _process_file_time_event(self, event: Dict) -> None:
        """Обработка изменения времени файла (timestomping)"""
        result = {
            'is_suspicious': True,
            'reasons': ['file_time_manipulation'],
            'score': 0.4,
            'attack_type': 'Timestomping',
            'severity': AlertSeverity.MEDIUM.value,
            'event_type': 'file_time_change'
        }

        result['process_name'] = event.get('process_name', '')
        result['filename'] = event.get('filename', '')

        self.event_bus.publish('edr.threat', result)

    def _process_alternate_data_stream(self, event: Dict) -> None:
        """Обработка Alternate Data Stream"""
        result = {
            'is_suspicious': True,
            'reasons': ['ads_creation'],
            'score': 0.45,
            'attack_type': 'Data Hiding',
            'severity': AlertSeverity.MEDIUM.value,
            'event_type': 'ads'
        }

        result['process_name'] = event.get('process_name', '')
        result['filename'] = event.get('filename', '')

        self.event_bus.publish('edr.threat', result)

    def _process_pipe_event(self, event: Dict) -> None:
        """Обработка создания/подключения к именованному каналу"""
        pipe_name = event.get('pipe_name', '').lower()

        suspicious_pipes = ['lsarpc', 'samr', 'netlogon', 'spoolss', 'srvsvc', 'wkssvc']

        for sus_pipe in suspicious_pipes:
            if sus_pipe in pipe_name:
                result = {
                    'is_suspicious': True,
                    'reasons': [f"suspicious_pipe:{pipe_name}"],
                    'score': 0.35,
                    'attack_type': 'Lateral Movement',
                    'severity': AlertSeverity.MEDIUM.value,
                    'event_type': 'pipe'
                }
                result['process_name'] = event.get('process_name', '')
                result['pipe_name'] = pipe_name

                self.event_bus.publish('edr.threat', result)
                break

    def _process_file_delete(self, event: Dict) -> None:
        """Обработка удаления файла"""
        filename = event.get('filename', '').lower()

        # Удаление важных системных файлов или логов
        important_files = ['.evtx', '.log', 'ntuser.dat', 'sam', 'system', 'security']

        for imp_file in important_files:
            if imp_file in filename:
                result = {
                    'is_suspicious': True,
                    'reasons': [f"important_file_deleted:{filename}"],
                    'score': 0.4,
                    'attack_type': 'Defense Evasion',
                    'severity': AlertSeverity.MEDIUM.value,
                    'event_type': 'file_delete'
                }
                result['process_name'] = event.get('process_name', '')
                result['filename'] = filename

                self.event_bus.publish('edr.threat', result)
                break

    def _process_clipboard_event(self, event: Dict) -> None:
        """Обработка события буфера обмена"""
        process_name = event.get('process_name', '').lower()

        if process_name not in ['explorer.exe', 'chrome.exe', 'firefox.exe', 'notepad.exe']:
            result = {
                'is_suspicious': True,
                'reasons': [f'unusual_clipboard_access:{process_name}'],
                'score': 0.3,
                'attack_type': 'Credential Access',
                'severity': AlertSeverity.LOW.value,
                'event_type': 'clipboard'
            }
            self.event_bus.publish('edr.threat', result)

    def _process_tampering_event(self, event: Dict) -> None:
        """Обработка события подмены процесса"""
        result = {
            'is_suspicious': True,
            'reasons': ['process_tampering'],
            'score': 0.6,
            'attack_type': 'Process Hollowing',
            'severity': AlertSeverity.HIGH.value,
            'event_type': 'process_tampering'
        }

        result['process_name'] = event.get('process_name', '')
        result['technique'] = event.get('technique', '')

        self.event_bus.publish('edr.threat', result)

    def _process_wmi_process_start(self, event: Dict) -> None:
        """Обработка WMI создания процесса"""
        event['source'] = 'wmi'
        self._process_process_event(event)

    def _process_wmi_process_stop(self, event: Dict) -> None:
        """Обработка WMI завершения процесса"""
        event['source'] = 'wmi'
        self._process_process_terminated(event)

    def _process_wmi_service_change(self, event: Dict) -> None:
        """Обработка изменения сервиса через WMI"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'service_change'
        }

        service_name = event.get('service_name', '').lower()
        state = event.get('state', '').lower()
        start_mode = event.get('start_mode', '').lower()

        # Создание сервиса с подозрительным именем
        suspicious_service_names = ['update', 'helper', 'support', 'service', 'driver', 'microsoft']
        for sus_name in suspicious_service_names:
            if sus_name in service_name:
                # Проверяем путь
                path_name = event.get('path_name', '').lower()
                for sus_path in self.suspicious_paths:
                    if sus_path in path_name:
                        result['is_suspicious'] = True
                        result['reasons'].append(f"suspicious_service_creation:{service_name}")
                        result['score'] += 0.4
                        result['attack_type'] = 'Persistence'
                        break
                break

        # Остановка защитных сервисов
        security_services = ['windefend', 'msmpeng', 'sense', 'wdnisdrv', 'wdfilter']
        for sec_svc in security_services:
            if sec_svc in service_name and state == 'stopped':
                result['is_suspicious'] = True
                result['reasons'].append(f"security_service_stopped:{service_name}")
                result['score'] += 0.5
                result['attack_type'] = 'Defense Evasion'
                break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['service_name'] = service_name
            result['state'] = state
            result['timestamp'] = time.time()

            if result['score'] > 0.5:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.3:
                result['severity'] = AlertSeverity.MEDIUM.value

            self.event_bus.publish('edr.threat', result)

    def _process_login_event(self, event: Dict) -> None:
        """Обработка события входа"""
        # Передаём в UBA
        self.event_bus.publish('auth.login', event)

        # Проверка на аномалии
        logon_type = event.get('logon_type', '')
        src_ip = event.get('src_ip', '')

        # RDP вход с необычного IP
        if logon_type == '10' and src_ip:
            # Проверка геолокации через ThreatIntel
            self.event_bus.publish('threat_intel.check_ip', {
                'ip': src_ip,
                'context': 'rdp_login',
                'username': event.get('username', '')
            })

    def _process_failed_login_event(self, event: Dict) -> None:
        """Обработка неудачного входа"""
        # Передаём в UBA
        self.event_bus.publish('auth.failed', event)

    def _analysis_loop(self) -> None:
        """Фоновый анализ событий"""
        while self.running:
            time.sleep(60)  # Каждую минуту

            # Анализ beaconing
            self._detect_beaconing()

            # Анализ цепочек событий
            self._analyze_event_chains()

            # Очистка старых событий
            self._cleanup_old_events()

    def _detect_beaconing(self) -> None:
        """Обнаружение C2 beaconing по сетевым соединениям (делегировано в EncryptedTrafficAnalyzer)"""

        # Собираем уникальные пары src_ip:dst_ip:dst_port
        unique_connections = set()
        cutoff = time.time() - 3600

        for event in self.network_events:
            if event.get('timestamp', 0) > cutoff:
                src_ip = event.get('src_ip', '')
                dst_ip = event.get('dst_ip', '')
                dst_port = event.get('dst_port', 0)
                process_name = event.get('process_name', '')

                if src_ip and dst_ip:
                    key = f"{src_ip}:{dst_ip}:{dst_port}"
                    unique_connections.add((key, process_name, event))

        # Для каждой уникальной пары проверяем beaconing через общий анализатор
        for key, process_name, event in unique_connections:
            # Публикуем событие для EncryptedTrafficAnalyzer вместо дублирования логики
            self.event_bus.publish('encrypted.traffic.check_beaconing', {
                'src_ip': event.get('src_ip'),
                'dst_ip': event.get('dst_ip'),
                'dst_port': event.get('dst_port'),
                'process_name': process_name,
                'timestamp': event.get('timestamp'),
                'packet_size': event.get('packet_size', 0)
            })

        # Оставляем только EDR-специфичную логику - анализ beaconing по процессам
        process_connections: Dict[str, List[float]] = defaultdict(list)

        for event in self.network_events:
            if event.get('timestamp', 0) > cutoff:
                process_name = event.get('process_name', '')
                if process_name:
                    process_connections[process_name].append(event.get('timestamp', 0))

        # Проверяем процессы с подозрительной периодичностью
        for process_name, timestamps in process_connections.items():
            if len(timestamps) < 10:
                continue

            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                if mean_interval > 0:
                    variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
                    cv = (variance ** 0.5) / mean_interval

                    # Низкая вариация + процесс из списка подозрительных
                    if cv < 0.15 and process_name.lower() in self.suspicious_processes:
                        result = {
                            'is_suspicious': True,
                            'reasons': ['process_beaconing', f'cv:{cv:.3f}'],
                            'score': 0.55,
                            'attack_type': 'C2 Beaconing',
                            'severity': AlertSeverity.HIGH.value,
                            'event_type': 'process_beaconing',
                            'details': {
                                'process_name': process_name,
                                'mean_interval': round(mean_interval, 2),
                                'variation': round(cv, 3),
                                'connections': len(timestamps)
                            }
                        }
                        self.event_bus.publish('edr.threat', result)
                        self.logger.warning(
                            f"Обнаружен beaconing процесса: {process_name} (интервал: {mean_interval:.1f}с, cv={cv:.3f})")

    def _analyze_event_chains(self) -> None:
        """Анализ цепочек событий для обнаружения сложных атак (оптимизированный)"""
        cutoff = time.time() - 600  # За последние 10 минут

        # Строим индексы для быстрого поиска
        processes_by_pid: Dict[int, Dict] = {}
        office_pids: Set[int] = set()

        with self._lock:
            # Индексируем процессы
            for event in self.process_events:
                if event.get('timestamp', 0) > cutoff:
                    pid = event.get('pid')
                    if pid:
                        processes_by_pid[pid] = event

                        process_name = event.get('process_name', '').lower()
                        if any(p in process_name for p in ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']):
                            office_pids.add(pid)

            # Проверяем только office процессы
            for office_pid in office_pids:
                if office_pid not in processes_by_pid:
                    continue

                office_event = processes_by_pid[office_pid]

                # Находим дочерние процессы через parent_pid (O(n) вместо O(n²))
                child_scripts = []
                for pid, event in processes_by_pid.items():
                    if event.get('parent_pid') == office_pid:
                        process_name = event.get('process_name', '').lower()
                        if any(s in process_name for s in ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']):
                            child_scripts.append((pid, event))

                # Проверяем сетевые соединения от дочерних процессов
                for script_pid, script_event in child_scripts:
                    # Используем индекс для быстрого поиска сетевых событий
                    network_events = [
                        e for e in self.network_events
                        if e.get('timestamp', 0) > script_event.get('timestamp', 0)
                           and e.get('process_id') == script_pid
                    ]

                    if network_events:
                        result = {
                            'is_suspicious': True,
                            'reasons': ['office_macro_chain'],
                            'score': 0.75,
                            'attack_type': 'Office Macro',
                            'severity': AlertSeverity.CRITICAL.value,
                            'event_type': 'attack_chain',
                            'details': {
                                'office_process': office_event.get('process_name'),
                                'script_process': script_event.get('process_name'),
                                'script_cmdline': script_event.get('command_line', '')[:200],
                                'network_target': f"{network_events[0].get('dst_ip')}:{network_events[0].get('dst_port')}"
                            }
                        }
                        self.event_bus.publish('edr.threat', result)

                        # Используем централизованное логирование через LoggingService
                        if hasattr(self.logger, 'security_alert'):
                            self.logger.security_alert(
                                module=self.name,
                                message=f"Обнаружена цепочка Office Macro: {office_event.get('process_name')} -> {script_event.get('process_name')} -> Network",
                                severity="CRITICAL",
                                data=result.get('details', {})
                            )
                        else:
                            # Fallback если LoggingService не обновлён
                            self.logger.critical(
                                f"Обнаружена цепочка Office Macro: {office_event.get('process_name')} -> "
                                f"{script_event.get('process_name')} -> Network"
                            )

                        break

    def _cleanup_old_events(self) -> None:
        """Очистка старых событий"""
        cutoff = time.time() - 7200  # Старше 2 часов

        with self._lock:
            for buffer in [self.process_events, self.file_events, self.registry_events,
                           self.network_events, self.dns_events, self.image_load_events]:
                while buffer and buffer[0].get('timestamp', 0) < cutoff:
                    buffer.popleft()

    def get_stats(self) -> Dict:
        """Получить статистику EDR"""
        with self._lock:
            return {
                'process_events': len(self.process_events),
                'file_events': len(self.file_events),
                'registry_events': len(self.registry_events),
                'network_events': len(self.network_events),
                'dns_events': len(self.dns_events),
                'image_load_events': len(self.image_load_events),
                'active_logs': len(self.event_log_handles),
                'wmi_active': len(self.wmi_watchers) > 0
            }

# ============================================================
# PROMETHEUS METRICS
# ============================================================


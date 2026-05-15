#!/usr/bin/env python3
"""SHARD IncidentReportGenerator Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
from shard_enterprise_complete import AlertSeverity
import time, threading, re, json
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

class IncidentReportGenerator(BaseModule):
    """Генерация автоматических отчётов об инцидентах (исправлен - защита от циклов, экранирование, ограничение частоты)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ReportGenerator", config, event_bus, logger)

        self.db_path = config.get('storage.sqlite.path', 'shard_siem.db')
        self.reports_dir = Path('reports')
        self.reports_dir.mkdir(exist_ok=True)

        # Ограничение частоты отчётов
        self._last_report_time: Dict[str, float] = {}
        self._report_cooldown = 300
        self._max_reports_per_hour = 20
        self._report_count: Dict[str, int] = defaultdict(int)
        self._report_count_reset = time.time()
        self._report_lock = threading.RLock()

        # ========== ЗАЩИТА ОТ ЦИКЛОВ ==========
        self._reported_investigations: Set[str] = set()
        self._investigation_lock = threading.RLock()
        # ====================================

        # Шаблоны рекомендаций
        self.recommendation_templates = {
            'Brute Force': [
                'Включить многофакторную аутентификацию',
                'Установить блокировку после N неудачных попыток',
                'Проверить сложность паролей'
            ],
            'Port Scan': [
                'Проверить правила файрвола',
                'Закрыть неиспользуемые порты',
                'Настроить rate limiting'
            ],
            'Web Attack': [
                'Проверить WAF правила',
                'Обновить веб-приложение',
                'Провести аудит кода'
            ],
            'DDoS': [
                'Включить DDoS защиту',
                'Связаться с провайдером',
                'Настроить фильтрацию трафика'
            ],
            'Lateral Movement': [
                'Изолировать затронутые системы',
                'Сменить пароли привилегированных учётных записей',
                'Проверить логи на других системах'
            ],
            'Data Exfiltration': [
                'Заблокировать подозрительный IP',
                'Проверить исходящие соединения',
                'Провести аудит доступа к данным'
            ],
            'DNS Tunnel': [
                'Заблокировать подозрительные DNS запросы',
                'Настроить DNS фильтрацию',
                'Проверить DNS логи'
            ]
        }

        self._lock = threading.RLock()
        self.event_bus.subscribe('investigation.completed', self.on_investigation)
        self.event_bus.subscribe('alert.detected', self.on_alert)

    def _escape_html(self, text: str) -> str:
        """Экранирование специальных символов HTML"""
        if not text:
            return ""
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace(
            "'", '&#39;')

    def _escape_text(self, text: str) -> str:
        """Безопасное форматирование текста для отчёта"""
        if not text:
            return "N/A"
        safe_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(text))
        return safe_text[:500]

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._cleanup_loop, daemon=True, name="Report-Cleanup").start()
        self.logger.info(f"Генератор отчётов запущен (директория: {self.reports_dir})")

    def stop(self) -> None:
        self.running = False
        self.logger.info("Генератор отчётов остановлен")

    def _cleanup_loop(self) -> None:
        """Очистка старых отчётов"""
        while self.running:
            time.sleep(3600)

            try:
                cutoff = time.time() - (30 * 86400)
                for report_file in self.reports_dir.glob('incident_*.txt'):
                    if report_file.stat().st_mtime < cutoff:
                        report_file.unlink()
                        self.logger.debug(f"Удалён старый отчёт: {report_file.name}")
            except Exception as e:
                self.logger.debug(f"Ошибка очистки отчётов: {e}")

    def on_investigation(self, investigation: Dict) -> None:
        """Генерация отчёта при завершении расследования (с защитой от циклов)"""
        inv_id = investigation.get('id')

        # ========== ЗАЩИТА ОТ ЦИКЛОВ ==========
        with self._investigation_lock:
            if inv_id in self._reported_investigations:
                self.logger.debug(f"Investigation {inv_id} already reported, skipping")
                return
            self._reported_investigations.add(inv_id)

            # Ограничиваем размер set'а
            if len(self._reported_investigations) > 1000:
                # Удаляем старые (первые 100)
                for _ in range(100):
                    if self._reported_investigations:
                        self._reported_investigations.pop()
        # ====================================

        alerts = investigation.get('alerts', [])
        if not alerts:
            return

        src_ip = investigation.get('src_ip', 'unknown')
        now = time.time()

        # Применяем ограничения частоты
        with self._report_lock:
            if now - self._report_count_reset > 3600:
                self._report_count.clear()
                self._report_count_reset = now

            if self._report_count.get('total', 0) >= self._max_reports_per_hour:
                self.logger.warning(f"Достигнут лимит отчётов, пропускаем расследование {inv_id}")
                return

            last_time = self._last_report_time.get(src_ip, 0)
            if now - last_time < self._report_cooldown:
                return

            self._last_report_time[src_ip] = now
            self._report_count['total'] = self._report_count.get('total', 0) + 1

        report = self.generate_report(investigation, alerts)
        self._save_report(inv_id, report)

    def on_alert(self, alert: Dict) -> None:
        """Автоматическая генерация отчёта для критических алертов (с ограничением частоты)"""
        if alert.get('severity') != AlertSeverity.CRITICAL.value:
            return

        src_ip = alert.get('src_ip', 'unknown')
        now = time.time()

        with self._report_lock:
            if now - self._report_count_reset > 3600:
                self._report_count.clear()
                self._report_count_reset = now

            if self._report_count.get('total', 0) >= self._max_reports_per_hour:
                self.logger.warning(f"Достигнут лимит отчётов ({self._max_reports_per_hour}/час), пропускаем")
                return

            last_time = self._last_report_time.get(src_ip, 0)
            if now - last_time < self._report_cooldown:
                self.logger.debug(f"Пропускаем отчёт для {src_ip} (cooldown {self._report_cooldown}с)")
                return

            self._last_report_time[src_ip] = now
            self._report_count['total'] = self._report_count.get('total', 0) + 1
            self._report_count[src_ip] = self._report_count.get(src_ip, 0) + 1

        investigation = {
            'id': f"INV-{int(now)}-{src_ip.replace('.', '_')[:10]}",
            'start_time': alert.get('timestamp', now),
            'end_time': now,
            'severity': alert.get('severity'),
            'stage': alert.get('kill_chain', {}).get('stage', 'unknown'),
            'src_ip': src_ip,
            'dst_ip': alert.get('dst_ip', 'N/A'),
            'conclusion': f"Критический алерт: {alert.get('attack_type')}",
            'recommendations': self._get_recommendations(alert.get('attack_type', 'Unknown'))
        }

        report = self.generate_report(investigation, [alert])
        self._save_report(investigation['id'], report)

    def generate_report(self, investigation: Dict, alerts: List[Dict]) -> str:
        """Генерация полного отчёта (с экранированием данных)"""
        inv = investigation

        inv_id = self._escape_text(inv.get('id', 'N/A'))
        start_time = datetime.fromtimestamp(inv.get('start_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        end_time = datetime.fromtimestamp(inv.get('end_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        severity = self._escape_text(inv.get('severity', 'UNKNOWN'))
        stage = self._escape_text(inv.get('stage', 'N/A'))
        conclusion = self._escape_text(inv.get('conclusion', 'Нет данных'))

        report = f"""
═══════════════════════════════════════════════════════════════════════════
                    ОТЧЁТ ОБ ИНЦИДЕНТЕ БЕЗОПАСНОСТИ
═══════════════════════════════════════════════════════════════════════════

ID инцидента: {inv_id}
Время начала: {start_time}
Время завершения: {end_time}
Серьёзность: {severity}
Стадия по MITRE ATT&CK: {stage}

───────────────────────────────────────────────────────────────────────────
1. КРАТКОЕ ОПИСАНИЕ
───────────────────────────────────────────────────────────────────────────
{conclusion}

───────────────────────────────────────────────────────────────────────────
2. ЗАТРОНУТЫЕ АКТИВЫ
───────────────────────────────────────────────────────────────────────────
"""
        src_ip = self._escape_text(inv.get('src_ip', 'N/A'))
        if not src_ip or src_ip == 'N/A':
            if alerts:
                src_ip = self._escape_text(alerts[0].get('src_ip', 'N/A'))
        report += f"Источник атаки: {src_ip}\n"

        dst_ips = set()
        dst_ports = set()
        for a in alerts:
            dst = a.get('dst_ip')
            if dst:
                dst_ips.add(self._escape_text(dst))
            port = a.get('dst_port')
            if port:
                dst_ports.add(str(port))

        report += f"Целевые системы: {', '.join(dst_ips) if dst_ips else 'N/A'}\n"
        report += f"Порты: {', '.join(dst_ports) if dst_ports else 'N/A'}\n"

        attack_types = set(self._escape_text(a.get('attack_type', 'Unknown')) for a in alerts)
        report += f"Типы атак: {', '.join(attack_types)}\n"

        report += f"""
───────────────────────────────────────────────────────────────────────────
3. ХРОНОЛОГИЯ СОБЫТИЙ
───────────────────────────────────────────────────────────────────────────
"""
        sorted_alerts = sorted(alerts, key=lambda x: x.get('timestamp', 0))

        for i, alert in enumerate(sorted_alerts[:50], 1):
            ts = datetime.fromtimestamp(alert.get('timestamp', 0)).strftime('%H:%M:%S')
            attack_type = self._escape_text(alert.get('attack_type', 'Unknown'))
            score = alert.get('score', 0)
            src = self._escape_text(alert.get('src_ip', 'unknown'))
            dst = f"{self._escape_text(alert.get('dst_ip', 'unknown'))}:{alert.get('dst_port', '')}"

            report += f"{i:2d}. {ts} — {attack_type} (score: {score:.3f})\n"
            report += f"    Источник: {src} → Цель: {dst}\n"

            explanation = alert.get('explanation')
            if explanation:
                safe_explanation = self._escape_text(explanation)[:100]
                report += f"    Причина: {safe_explanation}...\n"

            kill_chain = alert.get('kill_chain')
            if kill_chain:
                chain_stage = self._escape_text(kill_chain.get('stage', 'unknown'))
                event_count = kill_chain.get('event_count', 0)
                report += f"    Цепочка: {chain_stage}, событий: {event_count}\n"

            report += "\n"

        report += f"""
───────────────────────────────────────────────────────────────────────────
4. РЕКОМЕНДАЦИИ
───────────────────────────────────────────────────────────────────────────
"""
        recommendations = inv.get('recommendations', [])
        if not recommendations:
            for attack_type in attack_types:
                recommendations.extend(self._get_recommendations(attack_type))

        for i, rec in enumerate(set(recommendations), 1):
            report += f"{i}. {self._escape_text(rec)}\n"

        report += f"""
───────────────────────────────────────────────────────────────────────────
5. ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ
───────────────────────────────────────────────────────────────────────────
Всего алертов: {len(alerts)}
Максимальный score: {max((a.get('score', 0) for a in alerts), default=0):.3f}
Средний confidence: {sum(a.get('confidence', 0) for a in alerts) / max(1, len(alerts)):.3f}

"""
        for alert in alerts:
            ti = alert.get('threat_intel')
            if ti:
                sources = ', '.join(self._escape_text(s) for s in ti.get('sources', []))
                report += f"Threat Intelligence для {self._escape_text(alert.get('src_ip', 'N/A'))}:\n"
                report += f"  Источники: {sources}\n"
                report += f"  Score: {ti.get('score', 0):.2f}\n"

                country = ti.get('country')
                if country:
                    report += f"  Страна: {self._escape_text(country)}\n"
                break

        report += """
═══════════════════════════════════════════════════════════════════════════
                            КОНЕЦ ОТЧЁТА
═══════════════════════════════════════════════════════════════════════════
"""
        return report

    def generate_html_report(self, investigation: Dict, alerts: List[Dict]) -> str:
        """Генерация HTML отчёта (с полным экранированием)"""
        inv = investigation

        inv_id = self._escape_html(inv.get('id', 'N/A'))
        start_time = datetime.fromtimestamp(inv.get('start_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        end_time = datetime.fromtimestamp(inv.get('end_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        severity = self._escape_html(inv.get('severity', 'UNKNOWN'))
        stage = self._escape_html(inv.get('stage', 'N/A'))
        conclusion = self._escape_html(inv.get('conclusion', 'Нет данных'))

        severity_class = f"severity-{severity}"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline';">
    <title>SHARD Incident Report - {inv_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .header-info {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 20px 0; }}
        .info-item {{ padding: 10px; background: #f8f9fa; border-radius: 5px; }}
        .info-label {{ font-weight: bold; color: #666; }}
        .info-value {{ color: #333; }}
        .severity-CRITICAL {{ color: #dc3545; font-weight: bold; }}
        .severity-HIGH {{ color: #fd7e14; font-weight: bold; }}
        .severity-MEDIUM {{ color: #ffc107; }}
        .severity-LOW {{ color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .recommendations {{ background: #e7f3ff; padding: 15px; border-radius: 5px; }}
        .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SHARD SIEM - Отчёт об инциденте</h1>

        <div class="header-info">
            <div class="info-item">
                <span class="info-label">ID инцидента:</span>
                <span class="info-value">{inv_id}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Время начала:</span>
                <span class="info-value">{start_time}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Серьёзность:</span>
                <span class="info-value {severity_class}">{severity}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Стадия MITRE ATT&amp;CK:</span>
                <span class="info-value">{stage}</span>
            </div>
        </div>

        <h2>1. Краткое описание</h2>
        <p>{conclusion}</p>

        <h2>2. Хронология событий</h2>
        <table>
            <tr>
                <th>Время</th>
                <th>Тип атаки</th>
                <th>Источник</th>
                <th>Цель</th>
                <th>Score</th>
            </tr>
"""

        for alert in sorted(alerts, key=lambda x: x.get('timestamp', 0))[:50]:
            ts = datetime.fromtimestamp(alert.get('timestamp', 0)).strftime('%H:%M:%S')
            attack_type = self._escape_html(alert.get('attack_type', 'Unknown'))
            src = self._escape_html(alert.get('src_ip', 'unknown'))
            dst = f"{self._escape_html(alert.get('dst_ip', 'unknown'))}:{alert.get('dst_port', '')}"
            score = alert.get('score', 0)

            html += f"""
            <tr>
                <td>{ts}</td>
                <td>{attack_type}</td>
                <td>{src}</td>
                <td>{dst}</td>
                <td>{score:.3f}</td>
            </tr>
"""

        html += """
        </table>

        <h2>3. Рекомендации</h2>
        <div class="recommendations">
            <ul>
"""

        for rec in inv.get('recommendations', ['Провести дополнительный анализ']):
            html += f"                <li>{self._escape_html(rec)}</li>\n"

        html += """
            </ul>
        </div>

        <div class="footer">
            SHARD Enterprise SIEM | Отчёт сгенерирован автоматически
        </div>
    </div>
</body>
</html>
"""
        return html

    def _get_recommendations(self, attack_type: str) -> List[str]:
        """Получить рекомендации для типа атаки"""
        return self.recommendation_templates.get(attack_type,
                                                 ['Провести дополнительный анализ', 'Проверить логи',
                                                  'Усилить мониторинг'])

    def _save_report(self, incident_id: str, report: str) -> None:
        """Сохранение отчёта в файл"""
        safe_id = re.sub(r'[^a-zA-Z0-9\-_]', '_', str(incident_id))[:50]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.reports_dir / f"incident_{safe_id}_{timestamp}.txt"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            self.logger.info(f"Отчёт сохранён: {filename}")
        except Exception as e:
            self.logger.error(f"Ошибка сохранения отчёта: {e}")

    def get_recent_reports(self, limit: int = 10) -> List[Dict]:
        """Получить список последних отчётов"""
        reports = []
        try:
            for f in sorted(self.reports_dir.glob('incident_*.txt'),
                            key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
                reports.append({
                    'filename': f.name,
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                })
        except Exception as e:
            self.logger.error(f"Ошибка чтения отчётов: {e}")
        return reports

    def get_stats(self) -> Dict:
        """Получить статистику генератора отчётов"""
        with self._report_lock:
            with self._investigation_lock:
                return {
                    'reports_dir': str(self.reports_dir),
                    'reports_count': len(list(self.reports_dir.glob('incident_*.txt'))),
                    'reports_today': self._report_count.get('total', 0),
                    'max_reports_per_hour': self._max_reports_per_hour,
                    'cooldown_seconds': self._report_cooldown,
                    'reported_investigations': len(self._reported_investigations)
                }

# ============================================================
# 6️⃣ WEB DASHBOARD
# ============================================================
# ============================================================
# HTTP ОБРАБОТЧИК ДЛЯ ДАШБОРДА (вынесен наружу - пункт 77)
# ============================================================


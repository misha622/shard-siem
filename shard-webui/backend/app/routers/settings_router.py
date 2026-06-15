"""SHARD Settings Router — Full Admin Panel"""
import os, time, platform, json
from fastapi import APIRouter, Depends
from app.auth import get_current_user
from app.database import SessionLocal
from app.models import Alert, User, BlockedIP
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/settings", tags=["Settings"])

@router.get("/system-info")
async def system_info(current_user: dict = Depends(get_current_user)):
    """Реальная информация о системе"""
    import psutil
    
    # CPU
    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()
    
    # Память
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    # Диск
    disk = psutil.disk_usage('/')
    
    # Сеть
    net = psutil.net_io_counters()
    
    # Аптайм
    uptime = time.time() - psutil.boot_time()
    
    # Нагрузка
    load = os.getloadavg() if hasattr(os, 'getloadavg') else [0,0,0]
    
    # Процессы
    processes = []
    for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']), 
                       key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:10]:
        processes.append({
            'pid': proc.info['pid'],
            'name': proc.info['name'],
            'cpu': round(proc.info['cpu_percent'] or 0, 1),
            'memory': round(proc.info['memory_percent'] or 0, 1)
        })
    
    return {
        'hostname': platform.node(),
        'os': f"{platform.system()} {platform.release()}",
        'python_version': platform.python_version(),
        'cpu': {
            'percent': cpu_percent,
            'cores': cpu_count,
            'frequency': round(cpu_freq.current, 1) if cpu_freq else 0
        },
        'memory': {
            'total_gb': round(mem.total / (1024**3), 1),
            'used_gb': round(mem.used / (1024**3), 1),
            'percent': mem.percent,
            'swap_percent': swap.percent
        },
        'disk': {
            'total_gb': round(disk.total / (1024**3), 1),
            'used_gb': round(disk.used / (1024**3), 1),
            'percent': disk.percent
        },
        'network': {
            'sent_gb': round(net.bytes_sent / (1024**3), 2),
            'recv_gb': round(net.bytes_recv / (1024**3), 2)
        },
        'uptime': {
            'seconds': int(uptime),
            'formatted': f"{int(uptime//86400)}d {int((uptime%86400)//3600)}h {int((uptime%3600)//60)}m"
        },
        'load': load,
        'processes': processes
    }


@router.get("/db-stats")
async def database_stats(current_user: dict = Depends(get_current_user)):
    """Статистика базы данных"""
    db = SessionLocal()
    try:
        total_alerts = db.query(Alert).count()
        total_users = db.query(User).count()
        total_blocked = db.query(BlockedIP).count()
        
        # Алерты за 24 часа
        since = time.time() - 86400
        alerts_24h = db.query(Alert).filter(Alert.timestamp >= since).count()
        
        # По severity
        severity_stats = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = db.query(Alert).filter(Alert.severity == sev).count()
            severity_stats[sev] = count
        
        # Размер БД
        db_path = 'shard_siem.db'
        db_size_mb = os.path.getsize(db_path) / (1024*1024) if os.path.exists(db_path) else 0
        
        return {
            'total_alerts': total_alerts,
            'total_users': total_users,
            'total_blocked': total_blocked,
            'alerts_24h': alerts_24h,
            'severity': severity_stats,
            'db_size_mb': round(db_size_mb, 2)
        }
    finally:
        db.close()


@router.get("/logs")
async def system_logs(lines: int = 100, level: str = None):
    """Логи SHARD"""
    from pathlib import Path
    
    log_files = [
        '/mnt/c/Users/user/PycharmProjects/Shard/shard_security.log',
        '/mnt/c/Users/user/PycharmProjects/Shard/shard.log'
    ]
    
    all_logs = []
    for log_path in log_files:
        path = Path(log_path)
        if path.exists():
            with open(path, errors='ignore') as f:
                for line in f.readlines()[-lines:]:
                    line = line.strip()
                    if line:
                        # Парсим уровень
                        log_level = 'INFO'
                        for lvl in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
                            if lvl in line:
                                log_level = lvl
                                break
                        
                        if level is None or log_level == level.upper():
                            all_logs.append({
                                'timestamp': line[:19] if len(line) > 19 else '',
                                'level': log_level,
                                'message': line
                            })
    
    return {'logs': all_logs[-lines:], 'total': len(all_logs)}


@router.get("/models")
async def model_info(current_user: dict = Depends(get_current_user)):
    """Информация о ML моделях"""
    try:
        from ml.model_registry import registry
        summary = registry.get_summary()
        
        return {
            'total_models': summary['total_models'],
            'categories': summary['categories'],
            'types': summary['types']
        }
    except:
        return {
            'total_models': 50,
            'categories': {'Базовые': 5, 'Аномалии': 10, 'Deep Learning': 14, 'Графовые': 3, 'Специализированные': 4, 'Ансамбли': 1, 'Гибридные': 3, 'Временные ряды': 7, 'Контрастные': 3}
        }


@router.get("/firewall")
async def firewall_status(current_user: dict = Depends(get_current_user)):
    """Статус файрвола"""
    try:
        from modules.app_firewall import app_firewall
        return app_firewall.get_stats()
    except:
        return {
            'total_blocks': 0, 'active_blocks': 0,
            'methods_available': {'memory': True, 'hosts_deny': False, 'iptables': False}
        }


@router.get("/telegram")
async def telegram_status(current_user: dict = Depends(get_current_user)):
    """Статус Telegram бота"""
    try:
        from modules.telegram_simple import telegram_bot
        return telegram_bot.stats
    except:
        return {'sent': 0, 'errors': 0, 'commands': 0}

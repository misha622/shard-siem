"""
SQLite database for SHARD Enterprise SIEM
Persistent storage for users, alerts, blocked IPs
"""
import aiosqlite
import os
import uuid
import bcrypt
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "shard.db")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    if not hashed: return False
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except:
        return False


class Database:
    def __init__(self):
        self.db_path = DB_PATH
        self._initialized = False
    
    async def init(self):
        """Initialize database tables"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    company TEXT,
                    job_title TEXT,
                    role TEXT DEFAULT 'viewer',
                    hashed_password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    agree_updates INTEGER DEFAULT 0
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_lat REAL,
                    source_lon REAL,
                    source_country TEXT,
                    source_city TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol TEXT,
                    description TEXT,
                    threat_score REAL DEFAULT 0,
                    is_blocked INTEGER DEFAULT 0,
                    blocked_at TIMESTAMP,
                    raw_payload TEXT
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    reason TEXT,
                    blocked_by TEXT,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_permanent INTEGER DEFAULT 0
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS email_settings (
                    user_id TEXT PRIMARY KEY,
                    alert_critical INTEGER DEFAULT 1,
                    alert_high INTEGER DEFAULT 1,
                    alert_medium INTEGER DEFAULT 0,
                    ip_blocked INTEGER DEFAULT 1,
                    ip_unblocked INTEGER DEFAULT 0,
                    system_health INTEGER DEFAULT 1,
                    report_weekly INTEGER DEFAULT 0,
                    login_new_device INTEGER DEFAULT 1,
                    password_changed INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS geo_cache (
                    ip TEXT PRIMARY KEY,
                    latitude REAL,
                    longitude REAL,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.commit()
        
        self._initialized = True
        
        # Create default users if not exist
        await self._create_default_users()
        # Create sample alerts
        await self._create_sample_alerts()
        
        logger.info(f"Database initialized at {self.db_path}")
    
    async def _create_default_users(self):
        """Create admin and viewer if they don't exist"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT id FROM users WHERE username = 'admin'")
            if not await cursor.fetchone():
                await db.execute(
                    "INSERT INTO users (id, username, email, first_name, last_name, role, hashed_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), "admin", "admin@shard.local", "Admin", "User", "admin", hash_password("admin123"))
                )
                await db.execute(
                    "INSERT INTO email_settings (user_id) VALUES ((SELECT id FROM users WHERE username='admin'))"
                )
            
            cursor = await db.execute("SELECT id FROM users WHERE username = 'viewer'")
            if not await cursor.fetchone():
                await db.execute(
                    "INSERT INTO users (id, username, email, first_name, last_name, role, hashed_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), "viewer", "viewer@shard.local", "Viewer", "User", "viewer", hash_password("viewer123"))
                )
                await db.execute(
                    "INSERT INTO email_settings (user_id) VALUES ((SELECT id FROM users WHERE username='viewer'))"
                )
            
            await db.commit()
    
    async def _create_sample_alerts(self):
        """Create sample alerts if table is empty"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM alerts")
            count = (await cursor.fetchone())[0]
            if count > 0:
                return
            
            import random
            sample_alerts = [
                ("DDoS", "CRITICAL", "45.33.32.156", 37.7749, -122.4194, "US", "San Francisco", "192.168.1.100", 443, "TCP", "Large scale DDoS attack", 95.0),
                ("SQL Injection", "HIGH", "103.224.182.243", 28.6139, 77.2090, "IN", "New Delhi", "192.168.1.100", 80, "HTTP", "SQL injection attempt", 85.0),
                ("Port Scan", "MEDIUM", "78.128.113.94", 50.0755, 14.4378, "CZ", "Prague", "192.168.1.100", 22, "TCP", "Aggressive port scanning", 60.0),
                ("Malware", "CRITICAL", "185.220.101.34", 52.5200, 13.4050, "DE", "Berlin", "192.168.1.50", 445, "SMB", "Ransomware variant", 98.0),
                ("Brute Force", "HIGH", "91.121.87.45", 48.8566, 2.3522, "FR", "Paris", "192.168.1.100", 22, "SSH", "SSH brute force", 80.0),
                ("XSS", "MEDIUM", "198.51.100.23", 35.6762, 139.6503, "JP", "Tokyo", "192.168.1.200", 443, "HTTPS", "XSS in search form", 55.0),
                ("Phishing", "HIGH", "203.0.113.45", -33.8688, 151.2093, "AU", "Sydney", "192.168.1.150", 443, "HTTPS", "Phishing email campaign", 75.0),
                ("Data Exfiltration", "CRITICAL", "176.9.0.55", 51.1657, 10.4515, "DE", "Frankfurt", "192.168.1.100", 3306, "MySQL", "Suspicious data transfer", 92.0),
            ]
            
            for alert in sample_alerts:
                await db.execute(
                    "INSERT INTO alerts (id, timestamp, alert_type, severity, source_ip, source_lat, source_lon, source_country, source_city, destination_ip, destination_port, protocol, description, threat_score) VALUES (?, datetime('now', '-' || ? || ' minutes'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), str(random.randint(1, 1440)), *alert)
                )
            
            await db.commit()
            logger.info(f"Created {len(sample_alerts)} sample alerts")
    
    # ========== User methods ==========
    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def create_user(self, user_data: dict) -> str:
        user_id = str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO users (id, username, email, first_name, last_name, company, job_title, role, hashed_password, agree_updates) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, user_data["username"], user_data["email"], user_data.get("first_name", ""), 
                 user_data.get("last_name", ""), user_data.get("company", ""), user_data.get("job_title", ""),
                 "viewer", hash_password(user_data["password"]), 1 if user_data.get("agree_updates") else 0)
            )
            await db.execute("INSERT INTO email_settings (user_id) VALUES (?)", (user_id,))
            await db.commit()
        return user_id
    
    async def update_last_login(self, user_id: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
            await db.commit()
    
    async def change_password(self, user_id: str, new_password: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE users SET hashed_password = ? WHERE id = ?", (hash_password(new_password), user_id))
            await db.commit()
    
    async def get_all_users(self) -> List[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT id, username, email, role FROM users")
            return [dict(row) for row in await cursor.fetchall()]
    
    # ========== Alert methods ==========
    async def add_alert(self, alert_data: dict) -> str:
        alert_id = str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO alerts (id, timestamp, alert_type, severity, source_ip, source_lat, source_lon, 
                   source_country, source_city, destination_ip, destination_port, protocol, description, threat_score)
                   VALUES (?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert_id, alert_data.get("timestamp"), alert_data["alert_type"], alert_data["severity"],
                 alert_data["source_ip"], alert_data.get("source_lat"), alert_data.get("source_lon"),
                 alert_data.get("source_country"), alert_data.get("source_city"),
                 alert_data.get("destination_ip"), alert_data.get("destination_port"),
                 alert_data.get("protocol"), alert_data.get("description", ""), alert_data.get("threat_score", 0))
            )
            await db.commit()
        return alert_id
    
    async def get_alerts(self, params: dict) -> tuple:
        conditions = []
        values = []
        
        if params.get("alert_type"):
            conditions.append("alert_type = ?")
            values.append(params["alert_type"])
        if params.get("severity"):
            conditions.append("severity = ?")
            values.append(params["severity"])
        if params.get("source_ip"):
            conditions.append("source_ip LIKE ?")
            values.append(f"%{params['source_ip']}%")
        if params.get("destination_ip"):
            conditions.append("destination_ip LIKE ?")
            values.append(f"%{params['destination_ip']}%")
        if params.get("search"):
            conditions.append("(description LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ?)")
            s = f"%{params['search']}%"
            values.extend([s, s, s])
        
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        sort_by = params.get("sort_by", "timestamp")
        sort_order = "DESC" if params.get("sort_order", "desc") == "desc" else "ASC"
        page = params.get("page", 1)
        page_size = params.get("page_size", 50)
        offset = (page - 1) * page_size
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            cursor = await db.execute(f"SELECT COUNT(*) FROM alerts{where}", values)
            total = (await cursor.fetchone())[0]
            
            cursor = await db.execute(
                f"SELECT * FROM alerts{where} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
                values + [page_size, offset]
            )
            alerts = [dict(row) for row in await cursor.fetchall()]
        
        return alerts, total
    
    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def block_alert_source(self, alert_id: str, blocked_by: str) -> Optional[str]:
        alert = await self.get_alert_by_id(alert_id)
        if not alert:
            return None
        
        block_id = str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO blocked_ips (id, ip_address, reason, blocked_by, expires_at, is_permanent) VALUES (?, ?, ?, ?, datetime('now', '+24 hours'), 0)",
                (block_id, alert["source_ip"], f"Blocked from alert: {alert['alert_type']}", blocked_by)
            )
            await db.execute("UPDATE alerts SET is_blocked = 1, blocked_at = CURRENT_TIMESTAMP WHERE source_ip = ?", (alert["source_ip"],))
            await db.commit()
        return block_id
    
    async def get_alerts_for_map(self) -> List[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT source_ip, source_lat, source_lon, source_country, source_city, alert_type, severity, threat_score, timestamp FROM alerts WHERE source_lat IS NOT NULL ORDER BY timestamp DESC LIMIT 100"
            )
            return [dict(row) for row in await cursor.fetchall()]
    
    # ========== Blocked IP methods ==========
    async def get_blocked_ips(self) -> List[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
            return [dict(row) for row in await cursor.fetchall()]
    
    async def block_ip(self, ip_address: str, reason: str, blocked_by: str, is_permanent: bool = False) -> str:
        block_id = str(uuid.uuid4())
        expires = None if is_permanent else "datetime('now', '+24 hours')"
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                f"INSERT INTO blocked_ips (id, ip_address, reason, blocked_by, expires_at, is_permanent) VALUES (?, ?, ?, ?, {expires}, ?)",
                (block_id, ip_address, reason, blocked_by, 1 if is_permanent else 0)
            )
            await db.execute("UPDATE alerts SET is_blocked = 1, blocked_at = CURRENT_TIMESTAMP WHERE source_ip = ?", (ip_address,))
            await db.commit()
        return block_id
    
    async def unblock_ip(self, block_id: str) -> Optional[str]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT ip_address FROM blocked_ips WHERE id = ?", (block_id,))
            row = await cursor.fetchone()
            if row:
                ip = row[0]
                await db.execute("DELETE FROM blocked_ips WHERE id = ?", (block_id,))
                await db.execute("UPDATE alerts SET is_blocked = 0, blocked_at = NULL WHERE source_ip = ?", (ip,))
                await db.commit()
                return ip
        return None
    
    # ========== Stats ==========
    async def get_stats(self) -> dict:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            cursor = await db.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = (await cursor.fetchone())[0]
            
            cursor = await db.execute("SELECT COUNT(*) FROM alerts WHERE is_blocked = 1")
            total_blocked = (await cursor.fetchone())[0]
            
            cursor = await db.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('CRITICAL', 'HIGH') AND timestamp > datetime('now', '-1 hour')")
            active_threats = (await cursor.fetchone())[0]
            
            cursor = await db.execute("SELECT alert_type, COUNT(*) as c FROM alerts GROUP BY alert_type")
            alerts_by_type = {row["alert_type"]: row["c"] for row in await cursor.fetchall()}
            
            cursor = await db.execute("SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as c FROM alerts WHERE timestamp > datetime('now', '-24 hours') GROUP BY hour ORDER BY hour")
            alerts_by_hour = {row["hour"]: row["c"] for row in await cursor.fetchall()}
            
            cursor = await db.execute("SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity")
            severity_dist = {row["severity"]: row["c"] for row in await cursor.fetchall()}
            
            cursor = await db.execute("SELECT source_ip, COUNT(*) as c FROM alerts GROUP BY source_ip ORDER BY c DESC LIMIT 10")
            top_attackers = [{"ip": row["source_ip"], "count": row["c"]} for row in await cursor.fetchall()]
            
            cursor = await db.execute("SELECT destination_ip, COUNT(*) as c FROM alerts GROUP BY destination_ip ORDER BY c DESC LIMIT 10")
            top_targets = [{"ip": row["destination_ip"], "count": row["c"]} for row in await cursor.fetchall()]
            
            return {
                "total_packets": total_alerts * 100,
                "total_alerts": total_alerts,
                "total_blocked": total_blocked,
                "active_threats": active_threats,
                "alerts_by_type": alerts_by_type,
                "alerts_by_hour": alerts_by_hour,
                "severity_distribution": severity_dist,
                "top_attackers": top_attackers,
                "top_targets": top_targets
            }
    
    # ========== Token methods ==========
    async def add_refresh_token(self, token: str, user_id: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT INTO refresh_tokens (token, user_id) VALUES (?, ?)", (token, user_id))
            await db.commit()
    
    async def get_user_by_refresh_token(self, token: str) -> Optional[str]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT user_id FROM refresh_tokens WHERE token = ?", (token,))
            row = await cursor.fetchone()
            return row[0] if row else None
    
    async def revoke_refresh_token(self, token: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
            await db.commit()
    
    # ========== Email settings ==========
    async def get_email_settings(self, user_id: str) -> Dict:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM email_settings WHERE user_id = ?", (user_id,))
            row = await cursor.fetchone()
            if row:
                d = dict(row)
                return {
                    "alert.critical": bool(d.get("alert_critical", 1)),
                    "alert.high": bool(d.get("alert_high", 1)),
                    "alert.medium": bool(d.get("alert_medium", 0)),
                    "ip.blocked": bool(d.get("ip_blocked", 1)),
                    "ip.unblocked": bool(d.get("ip_unblocked", 0)),
                    "system.health": bool(d.get("system_health", 1)),
                    "report.weekly": bool(d.get("report_weekly", 0)),
                    "login.new_device": bool(d.get("login_new_device", 1)),
                    "password.changed": bool(d.get("password_changed", 1)),
                }
            return {}
    
    async def update_email_settings(self, user_id: str, settings: Dict[str, bool]):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO email_settings (user_id, alert_critical, alert_high, alert_medium, ip_blocked, ip_unblocked, system_health, report_weekly, login_new_device, password_changed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    alert_critical=excluded.alert_critical, alert_high=excluded.alert_high,
                    alert_medium=excluded.alert_medium, ip_blocked=excluded.ip_blocked,
                    ip_unblocked=excluded.ip_unblocked, system_health=excluded.system_health,
                    report_weekly=excluded.report_weekly, login_new_device=excluded.login_new_device,
                    password_changed=excluded.password_changed
            """, (
                user_id,
                1 if settings.get("alert.critical", True) else 0,
                1 if settings.get("alert.high", True) else 0,
                1 if settings.get("alert.medium", False) else 0,
                1 if settings.get("ip.blocked", True) else 0,
                1 if settings.get("ip.unblocked", False) else 0,
                1 if settings.get("system.health", True) else 0,
                1 if settings.get("report.weekly", False) else 0,
                1 if settings.get("login.new_device", True) else 0,
                1 if settings.get("password.changed", True) else 0,
            ))
            await db.commit()
    
    # ========== Geo cache ==========
    async def get_geo_cache(self, ip: str) -> Optional[Dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def set_geo_cache(self, ip: str, data: dict):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO geo_cache (ip, latitude, longitude, country, city, isp, updated_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                (ip, data.get("lat"), data.get("lon"), data.get("country"), data.get("city"), data.get("isp"))
            )
            await db.commit()


# Глобальный экземпляр базы данных
db = Database()

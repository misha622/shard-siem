import bcrypt, logging, ipaddress
from sqlalchemy.orm import Session
from sqlalchemy import func as sa_func
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from app.models import Base, engine, SessionLocal, Company, User, Alert, BlockedIP, RefreshToken, EmailSettings

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    if not hashed: return False
    try: return bcrypt.checkpw(plain.encode(), hashed.encode())
    except: return False

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(Company).first():
            companies = [
                Company(name="Headquarters", ip_ranges=["192.168.1.0/24","10.0.0.0/16"], max_alerts_per_day=50000),
                Company(name="Branch Office A", ip_ranges=["172.16.0.0/20"], max_alerts_per_day=10000),
                Company(name="Branch Office B", ip_ranges=["10.100.0.0/16"], max_alerts_per_day=10000),
            ]
            db.add_all(companies)
            db.commit()
            hq = db.query(Company).filter_by(name="Headquarters").first()
            ba = db.query(Company).filter_by(name="Branch Office A").first()
            users = [
                User(username="admin", email="admin@shard.local", hashed_password=hash_password("admin123"), role="admin", first_name="Admin"),
                User(username="viewer", email="viewer@shard.local", hashed_password=hash_password("viewer123"), role="viewer", company_id=hq.id, first_name="HQ Viewer"),
                User(username="branch_user", email="branch@shard.local", hashed_password=hash_password("branch123"), role="viewer", company_id=ba.id, first_name="Branch User"),
            ]
            db.add_all(users)
            db.commit()
            alerts_data = [
                ("45.33.32.156","192.168.1.100",443,"TCP","DDoS","CRITICAL","DDoS attack detected",95.0,hq.id),
                ("103.224.182.243","192.168.1.50",80,"HTTP","SQL Injection","HIGH","SQL injection attempt",85.0,hq.id),
                ("78.128.113.94","172.16.0.10",22,"TCP","Port Scan","MEDIUM","Port scanning activity",60.0,ba.id),
                ("185.220.101.34","172.16.0.20",445,"SMB","Malware","CRITICAL","Ransomware detected",98.0,ba.id),
                ("91.121.87.45","10.100.0.5",22,"SSH","Brute Force","HIGH","SSH brute force",80.0,companies[2].id),
            ]
            for i, (src,dst,port,proto,atype,sev,desc,score,cid) in enumerate(alerts_data):
                db.add(Alert(timestamp=datetime.utcnow()-timedelta(hours=i), alert_type=atype, severity=sev, source_ip=src, destination_ip=dst, destination_port=port, protocol=proto, description=desc, threat_score=score, company_id=cid))
            db.commit()
            logger.info(f"DB initialized: {len(companies)} companies, {len(users)} users, {len(alerts_data)} alerts")
    finally:
        db.close()

def get_user_by_username(username: str) -> Optional[User]:
    db = SessionLocal()
    try: return db.query(User).filter(User.username == username).first()
    finally: db.close()

def add_alert(data: dict) -> Alert:
    db = SessionLocal()
    try:
        alert = Alert(**data)
        db.add(alert)
        db.commit()
        return alert
    finally: db.close()

def get_alerts(filters: dict, company_id: Optional[int] = None) -> tuple:
    db = SessionLocal()
    try:
        q = db.query(Alert)
        if company_id is not None: q = q.filter(Alert.company_id == company_id)
        if filters.get("alert_type"): q = q.filter(Alert.alert_type == filters["alert_type"])
        if filters.get("severity"): q = q.filter(Alert.severity == filters["severity"])
        if filters.get("search"):
            s = f"%{filters['search']}%"
            q = q.filter(Alert.description.contains(s))
        total = q.count()
        page = filters.get("page", 1)
        page_size = min(filters.get("page_size", 50), 100)
        alerts = q.order_by(Alert.timestamp.desc()).offset((page-1)*page_size).limit(page_size).all()
        return alerts, total
    finally: db.close()

def block_alert_source(alert_id: int, blocked_by: str) -> Optional[BlockedIP]:
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert: return None
        blocked = BlockedIP(ip_address=alert.source_ip, reason=f"Blocked from alert: {alert.alert_type}", blocked_by=blocked_by, expires_at=datetime.utcnow()+timedelta(hours=24))
        db.add(blocked)
        db.query(Alert).filter(Alert.source_ip == alert.source_ip).update({"is_blocked": True, "blocked_at": datetime.utcnow()})
        db.commit()
        return blocked
    finally: db.close()

def get_blocked_ips() -> List[BlockedIP]:
    db = SessionLocal()
    try: return db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    finally: db.close()

def block_ip(ip_address: str, reason: str, blocked_by: str, is_permanent: bool = False) -> BlockedIP:
    db = SessionLocal()
    try:
        blocked = BlockedIP(ip_address=ip_address, reason=reason, blocked_by=blocked_by, is_permanent=is_permanent, expires_at=None if is_permanent else datetime.utcnow()+timedelta(hours=24))
        db.add(blocked)
        db.query(Alert).filter(Alert.source_ip == ip_address).update({"is_blocked": True, "blocked_at": datetime.utcnow()})
        db.commit()
        return blocked
    finally: db.close()

def get_companies() -> List[Company]:
    db = SessionLocal()
    try: return db.query(Company).filter(Company.is_active == True).all()
    finally: db.close()

def match_alert_to_company(alert_data: dict) -> Optional[int]:
    db = SessionLocal()
    try:
        for company in db.query(Company).filter(Company.is_active == True).all():
            if not company.ip_ranges: continue
            for r in company.ip_ranges:
                try:
                    net = ipaddress.ip_network(r, strict=False)
                    src = alert_data.get("source_ip","")
                    dst = alert_data.get("destination_ip","")
                    if (src and ipaddress.ip_address(src) in net) or (dst and ipaddress.ip_address(dst) in net):
                        return company.id
                except ValueError: continue
        return None
    finally: db.close()

def get_stats(company_id: Optional[int] = None) -> dict:
    db = SessionLocal()
    try:
        q = db.query(Alert)
        if company_id is not None: q = q.filter(Alert.company_id == company_id)
        total = q.count()
        blocked = q.filter(Alert.is_blocked == True).count()
        threats = q.filter(Alert.severity.in_(["CRITICAL","HIGH"]), Alert.timestamp >= datetime.utcnow()-timedelta(hours=1)).count()
        alerts_by_type = {}
        for row in db.query(Alert.alert_type, sa_func.count()).filter(Alert.company_id == company_id if company_id else True).group_by(Alert.alert_type).all():
            alerts_by_type[row[0]] = row[1]
        alerts_by_hour = {}
        for row in db.query(sa_func.strftime('%H:00', Alert.timestamp), sa_func.count()).filter(Alert.timestamp >= datetime.utcnow()-timedelta(hours=24)).group_by(sa_func.strftime('%H:00', Alert.timestamp)).all():
            alerts_by_hour[row[0]] = row[1]
        top_attackers = [{"ip": row[0], "count": row[1]} for row in db.query(Alert.source_ip, sa_func.count()).group_by(Alert.source_ip).order_by(sa_func.count().desc()).limit(10).all()]
        top_targets = [{"ip": row[0], "count": row[1]} for row in db.query(Alert.destination_ip, sa_func.count()).group_by(Alert.destination_ip).order_by(sa_func.count().desc()).limit(10).all()]
        return {"total_packets": total * 100, "total_alerts": total, "total_blocked": blocked, "active_threats": threats, "alerts_by_type": alerts_by_type, "alerts_by_hour": alerts_by_hour, "severity_distribution": {}, "top_attackers": top_attackers, "top_targets": top_targets}
    finally: db.close()

def update_last_login(user_id: int):
    db = SessionLocal()
    try: db.query(User).filter(User.id == user_id).update({"last_login": datetime.utcnow()}); db.commit()
    finally: db.close()

def get_all_users() -> List[User]:
    db = SessionLocal()
    try: return db.query(User).all()
    finally: db.close()

def get_user_by_id(user_id: int) -> Optional[User]:
    db = SessionLocal()
    try: return db.query(User).filter(User.id == user_id).first()
    finally: db.close()

def change_password(user_id: int, new_password: str):
    db = SessionLocal()
    try:
        db.query(User).filter(User.id == user_id).update({"hashed_password": hash_password(new_password)})
        db.commit()
    finally: db.close()

def get_alert_by_id(alert_id: int) -> Optional[Alert]:
    db = SessionLocal()
    try: return db.query(Alert).filter(Alert.id == alert_id).first()
    finally: db.close()

def get_alerts_for_map() -> List[Alert]:
    db = SessionLocal()
    try: return db.query(Alert).filter(Alert.source_lat.isnot(None)).order_by(Alert.timestamp.desc()).limit(100).all()
    finally: db.close()

def unblock_ip(block_id: int) -> Optional[str]:
    db = SessionLocal()
    try:
        blocked = db.query(BlockedIP).filter(BlockedIP.id == block_id).first()
        if blocked:
            ip = blocked.ip_address
            db.delete(blocked)
            db.query(Alert).filter(Alert.source_ip == ip).update({"is_blocked": False, "blocked_at": None})
            db.commit()
            return ip
        return None
    finally: db.close()

def add_refresh_token(token: str, user_id: int):
    db = SessionLocal()
    try: db.add(RefreshToken(token=token, user_id=user_id)); db.commit()
    finally: db.close()

def get_user_by_refresh_token(token: str) -> Optional[int]:
    db = SessionLocal()
    try:
        rt = db.query(RefreshToken).filter(RefreshToken.token == token).first()
        return rt.user_id if rt else None
    finally: db.close()

def revoke_refresh_token(token: str):
    db = SessionLocal()
    try: db.query(RefreshToken).filter(RefreshToken.token == token).delete(); db.commit()
    finally: db.close()

def get_email_settings(user_id: int) -> dict:
    db = SessionLocal()
    try:
        es = db.query(EmailSettings).filter(EmailSettings.user_id == user_id).first()
        if not es: es = EmailSettings(user_id=user_id); db.add(es); db.commit()
        return {"alert.critical": es.alert_critical, "alert.high": es.alert_high, "alert.medium": es.alert_medium, "ip.blocked": es.ip_blocked, "system.health": es.system_health, "report.weekly": es.report_weekly}
    finally: db.close()

def update_email_settings(user_id: int, settings: dict):
    db = SessionLocal()
    try:
        es = db.query(EmailSettings).filter(EmailSettings.user_id == user_id).first()
        if not es: es = EmailSettings(user_id=user_id); db.add(es)
        for k, v in settings.items():
            col = k.replace(".", "_")
            if hasattr(es, col): setattr(es, col, v)
        db.commit()
    finally: db.close()

def get_company_by_id(company_id: int) -> Optional[Company]:
    db = SessionLocal()
    try: return db.query(Company).filter(Company.id == company_id).first()
    finally: db.close()

# ========== Additional functions ==========
def create_user(data: dict) -> User:
    db = SessionLocal()
    try:
        user = User(
            username=data["username"],
            email=data.get("email", ""),
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            hashed_password=hash_password(data["password"]),
            role="viewer"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()

def get_alerts_for_map() -> List[Alert]:
    db = SessionLocal()
    try:
        return db.query(Alert).filter(Alert.source_lat.isnot(None)).order_by(Alert.timestamp.desc()).limit(100).all()
    finally:
        db.close()

def get_email_settings(user_id: int) -> dict:
    db = SessionLocal()
    try:
        es = db.query(EmailSettings).filter(EmailSettings.user_id == user_id).first()
        if not es:
            es = EmailSettings(user_id=user_id)
            db.add(es)
            db.commit()
        return {"alert.critical": es.alert_critical, "alert.high": es.alert_high,
                "alert.medium": es.alert_medium, "ip.blocked": es.ip_blocked,
                "system.health": es.system_health, "report.weekly": es.report_weekly}
    finally:
        db.close()

def update_email_settings(user_id: int, settings: dict):
    db = SessionLocal()
    try:
        es = db.query(EmailSettings).filter(EmailSettings.user_id == user_id).first()
        if not es:
            es = EmailSettings(user_id=user_id)
            db.add(es)
        col_map = {"alert.critical": "alert_critical", "alert.high": "alert_high",
                   "alert.medium": "alert_medium", "ip.blocked": "ip_blocked",
                   "system.health": "system_health", "report.weekly": "report_weekly"}
        for k, v in settings.items():
            if k in col_map:
                setattr(es, col_map[k], v)
        db.commit()
    finally:
        db.close()

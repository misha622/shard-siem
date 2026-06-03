import bcrypt, logging, ipaddress
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from models import Base, engine, SessionLocal, Company, User, Alert, BlockedIP, RefreshToken, EmailSettings

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
        return {"total_alerts": total, "blocked_ips": blocked, "active_threats": threats}
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

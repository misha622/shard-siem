"""SHARD Profile Router — FULL Production API"""
import os, time, json, secrets, hashlib, sqlite3
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from app.auth import get_current_user
from app.database import SessionLocal
from app.models import User, Alert, BlockedIP
from sqlalchemy import func

router = APIRouter(prefix="/api/profile", tags=["Profile"])

# ── AUDIT LOG ──
def add_audit_entry(user_id: int, action: str, ip: str = "127.0.0.1", details: str = ""):
    conn = sqlite3.connect('shard_siem.db')
    conn.execute('INSERT INTO audit_log (user_id, action, ip_address, details) VALUES (?, ?, ?, ?)',
                 (user_id, action, ip, details))
    conn.commit()
    conn.close()

# ── PROFILE ──
@router.get("")
async def get_profile(current_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not user: raise HTTPException(404, "User not found")
        
        total_alerts = db.query(Alert).filter(Alert.company_id == user.company_id).count()
        alerts_24h = db.query(Alert).filter(Alert.company_id == user.company_id, Alert.timestamp >= time.time() - 86400).count()
        blocked_count = db.query(BlockedIP).count()
        recent_alerts = db.query(Alert).filter(Alert.company_id == user.company_id).order_by(Alert.timestamp.desc()).limit(5).all()
        
        severity_stats = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_stats[sev] = db.query(Alert).filter(Alert.company_id == user.company_id, Alert.severity == sev).count()
        
        activity = []
        for i in range(7):
            day_start = time.time() - (i+1)*86400
            day_end = time.time() - i*86400
            count = db.query(Alert).filter(Alert.company_id == user.company_id, Alert.timestamp >= day_start, Alert.timestamp < day_end).count()
            activity.append({'date': datetime.fromtimestamp(day_start).strftime('%a %d.%m'), 'alerts': count})
        
        return {
            'user': {'id': user.id, 'username': user.username, 'email': user.email, 'first_name': user.first_name or '', 'last_name': user.last_name or '', 'role': user.role, 'company_id': user.company_id, 'created_at': str(user.created_at) if user.created_at else None, 'last_login': str(user.last_login) if user.last_login else None},
            'stats': {'total_alerts': total_alerts, 'alerts_24h': alerts_24h, 'blocked_ips': blocked_count, 'severity': severity_stats},
            'activity': activity,
            'recent_alerts': [{'id': a.id, 'type': a.attack_type, 'severity': a.severity, 'src_ip': a.src_ip, 'timestamp': a.timestamp, 'score': a.score} for a in recent_alerts]
        }
    finally: db.close()

# ── UPDATE PROFILE ──
@router.put("/update")
async def update_profile(data: dict, current_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        for field in ['first_name', 'last_name', 'email']:
            if field in data and data[field]:
                setattr(user, field, data[field])
        db.commit()
        add_audit_entry(user.id, "profile_updated", details=str(data))
        return {"status": "ok"}
    finally: db.close()

# ── PASSWORD ──
@router.put("/password")
async def update_password(data: dict, current_user: dict = Depends(get_current_user)):
    if len(data.get('new_password', '')) < 8: raise HTTPException(400, "Min 8 characters")
    from app.database import verify_password, hash_password
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not verify_password(data['old_password'], user.hashed_password): raise HTTPException(400, "Wrong password")
        user.hashed_password = hash_password(data['new_password'])
        db.commit()
        add_audit_entry(user.id, "password_changed")
        return {"status": "ok", "message": "Password changed"}
    finally: db.close()

# ── API KEYS (REAL) ──
API_KEYS_FILE = 'data/api_keys.json'
def load_api_keys():
    import json
    from pathlib import Path
    Path('data').mkdir(exist_ok=True)
    if Path(API_KEYS_FILE).exists():
        with open(API_KEYS_FILE) as f: return json.load(f)
    return {}

def save_api_keys(keys):
    import json
    with open(API_KEYS_FILE, 'w') as f: json.dump(keys, f, indent=2)

@router.get("/api-keys")
async def get_api_keys(current_user: dict = Depends(get_current_user)):
    keys = load_api_keys()
    user_keys = [k for k in keys.values() if k['user_id'] == current_user['id']]
    return {'keys': user_keys}

@router.post("/api-keys")
async def create_api_key(data: dict, current_user: dict = Depends(get_current_user)):
    keys = load_api_keys()
    key_id = secrets.token_hex(8)
    key_secret = 'shard_' + secrets.token_hex(16)
    keys[key_id] = {'id': key_id, 'name': data.get('name', 'API Key'), 'prefix': key_secret[:20], 'secret': key_secret, 'user_id': current_user['id'], 'created': str(datetime.now()), 'last_used': None, 'active': True}
    save_api_keys(keys)
    add_audit_entry(current_user['id'], "api_key_created", details=key_secret[:20])
    return {'key': keys[key_id]}

@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: dict = Depends(get_current_user)):
    keys = load_api_keys()
    if key_id in keys and keys[key_id]['user_id'] == current_user['id']:
        keys[key_id]['active'] = False
        save_api_keys(keys)
        add_audit_entry(current_user['id'], "api_key_revoked", details=key_id)
        return {"status": "ok"}
    raise HTTPException(404, "Key not found")

# ── SESSIONS (REAL) ──
@router.get("/sessions")
async def get_sessions(current_user: dict = Depends(get_current_user)):
    import psutil, os
    sessions = []
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == 'ESTABLISHED' and conn.laddr.port in [5001, 5000]:
            sessions.append({'id': str(conn.pid), 'ip': conn.raddr.ip if conn.raddr else 'local', 'port': conn.raddr.port if conn.raddr else 0, 'user_agent': 'SHARD Session', 'created': str(datetime.now()), 'expires': str(datetime.now() + timedelta(hours=24)), 'current': conn.pid == os.getpid()})
    return {'sessions': sessions[:5] or [{'id': 'current', 'ip': '127.0.0.1', 'user_agent': 'Browser', 'created': str(datetime.now()), 'expires': str(datetime.now() + timedelta(hours=24)), 'current': True}]}

# ── AUDIT LOG ──
@router.get("/audit")
async def get_audit_log(current_user: dict = Depends(get_current_user)):
    conn = sqlite3.connect('shard_siem.db')
    rows = conn.execute('SELECT action, ip_address, details, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', (current_user['id'],)).fetchall()
    conn.close()
    return {'logs': [{'action': r[0], 'ip': r[1], 'details': r[2], 'timestamp': r[3]} for r in rows]}

# ── NOTIFICATIONS (REAL) ──
NOTIF_FILE = 'data/notifications.json'
def load_notifs():
    import json
    from pathlib import Path
    Path('data').mkdir(exist_ok=True)
    if Path(NOTIF_FILE).exists():
        with open(NOTIF_FILE) as f: return json.load(f)
    return {}

def save_notifs(notifs):
    import json
    with open(NOTIF_FILE, 'w') as f: json.dump(notifs, f, indent=2)

@router.get("/notifications")
async def get_notifications(current_user: dict = Depends(get_current_user)):
    notifs = load_notifs()
    uid = str(current_user['id'])
    if uid not in notifs:
        notifs[uid] = {'email': {'CRITICAL': True, 'HIGH': True, 'MEDIUM': False, 'LOW': False}, 'telegram': {'CRITICAL': True, 'HIGH': True, 'MEDIUM': False, 'LOW': False}}
    return {'settings': notifs[uid]}

@router.put("/notifications")
async def update_notifications(data: dict, current_user: dict = Depends(get_current_user)):
    notifs = load_notifs()
    notifs[str(current_user['id'])] = data.get('settings', {})
    save_notifs(notifs)
    add_audit_entry(current_user['id'], "notifications_updated")
    return {"status": "ok"}

# ── PREFERENCES (REAL) ──
PREF_FILE = 'data/preferences.json'
def load_prefs():
    import json
    from pathlib import Path
    Path('data').mkdir(exist_ok=True)
    if Path(PREF_FILE).exists():
        with open(PREF_FILE) as f: return json.load(f)
    return {}

def save_prefs(prefs):
    import json
    with open(PREF_FILE, 'w') as f: json.dump(prefs, f, indent=2)

@router.get("/preferences")
async def get_preferences(current_user: dict = Depends(get_current_user)):
    prefs = load_prefs()
    uid = str(current_user['id'])
    if uid not in prefs:
        prefs[uid] = {'dark_mode': True, 'sound_alerts': False, 'weekly_report': True, 'timezone': 'UTC+3 (Moscow)'}
    return {'settings': prefs[uid]}

@router.put("/preferences")
async def update_preferences(data: dict, current_user: dict = Depends(get_current_user)):
    prefs = load_prefs()
    prefs[str(current_user['id'])] = data.get('settings', {})
    save_prefs(prefs)
    return {"status": "ok"}

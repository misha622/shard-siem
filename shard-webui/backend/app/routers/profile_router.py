"""SHARD Profile Router — Full User Profile API"""
import os, time, json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from app.auth import get_current_user
from app.database import SessionLocal, get_user_by_username, get_user_by_id, change_password
from app.models import User, Alert, BlockedIP
from sqlalchemy import func

router = APIRouter(prefix="/api/profile", tags=["Profile"])

@router.get("")
async def get_profile(current_user: dict = Depends(get_current_user)):
    """Полный профиль пользователя"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not user:
            raise HTTPException(404, "User not found")
        
        # Статистика алертов этого пользователя
        total_alerts = db.query(Alert).filter(Alert.company_id == user.company_id).count()
        alerts_24h = db.query(Alert).filter(
            Alert.company_id == user.company_id,
            Alert.timestamp >= time.time() - 86400
        ).count()
        
        # Заблокированные IP
        blocked_count = db.query(BlockedIP).count()
        
        # Последние алерты
        recent_alerts = db.query(Alert).filter(
            Alert.company_id == user.company_id
        ).order_by(Alert.timestamp.desc()).limit(5).all()
        
        # Статистика по severity
        severity_stats = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = db.query(Alert).filter(
                Alert.company_id == user.company_id,
                Alert.severity == sev
            ).count()
            severity_stats[sev] = count
        
        # Активность по дням
        activity = []
        for i in range(7):
            day_start = time.time() - (i+1)*86400
            day_end = time.time() - i*86400
            count = db.query(Alert).filter(
                Alert.company_id == user.company_id,
                Alert.timestamp >= day_start,
                Alert.timestamp < day_end
            ).count()
            activity.append({
                'date': datetime.fromtimestamp(day_start).strftime('%a %d.%m'),
                'alerts': count
            })
        
        return {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'role': user.role,
                'company_id': user.company_id,
                'created_at': str(user.created_at) if user.created_at else None,
                'last_login': str(user.last_login) if user.last_login else None
            },
            'stats': {
                'total_alerts': total_alerts,
                'alerts_24h': alerts_24h,
                'blocked_ips': blocked_count,
                'severity': severity_stats
            },
            'activity': activity,
            'recent_alerts': [{
                'id': a.id,
                'type': a.attack_type,
                'severity': a.severity,
                'src_ip': a.src_ip,
                'timestamp': a.timestamp,
                'score': a.score
            } for a in recent_alerts]
        }
    finally:
        db.close()


@router.put("/update")
async def update_profile(data: dict, current_user: dict = Depends(get_current_user)):
    """Обновить профиль"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not user:
            raise HTTPException(404, "User not found")
        
        # Разрешённые поля для обновления
        allowed_fields = ['first_name', 'last_name', 'email']
        for field in allowed_fields:
            if field in data and data[field]:
                setattr(user, field, data[field])
        
        db.commit()
        return {"status": "ok", "message": "Profile updated"}
    finally:
        db.close()


@router.put("/password")
async def update_password(data: dict, current_user: dict = Depends(get_current_user)):
    """Сменить пароль"""
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    
    if not old_password or not new_password:
        raise HTTPException(400, "Both old and new password required")
    
    if len(new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    
    from app.database import verify_password
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not verify_password(old_password, user.hashed_password):
            raise HTTPException(400, "Current password is incorrect")
        
        from app.database import hash_password
        user.hashed_password = hash_password(new_password)
        db.commit()
        return {"status": "ok", "message": "Password changed"}
    finally:
        db.close()


@router.get("/api-keys")
async def get_api_keys(current_user: dict = Depends(get_current_user)):
    """API ключи пользователя (заглушка — TODO: реальная реализация)"""
    return {
        'keys': [{
            'id': 1,
            'name': 'Default API Key',
            'prefix': 'shard_' + str(current_user["id"]) + '_' + str(int(time.time())),
            'created': str(datetime.now()),
            'last_used': None,
            'active': True
        }]
    }


@router.get("/sessions")
async def get_sessions(current_user: dict = Depends(get_current_user)):
    """Активные сессии пользователя"""
    return {
        'sessions': [{
            'id': 'current',
            'ip': '127.0.0.1',
            'user_agent': 'Browser',
            'created': str(datetime.now()),
            'expires': str(datetime.now() + timedelta(hours=24)),
            'current': True
        }]
    }


@router.get("/company")
async def get_company(current_user: dict = Depends(get_current_user)):
    """Информация о компании"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        from app.models import Company
        company = db.query(Company).filter(Company.id == user.company_id).first()
        if company:
            return {
                'name': company.name,
                'ip_ranges': company.ip_ranges,
                'max_alerts_per_day': company.max_alerts_per_day,
                'created_at': str(company.created_at) if company.created_at else None
            }
        return {'name': 'N/A', 'ip_ranges': []}
    finally:
        db.close()

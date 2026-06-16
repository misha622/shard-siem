#!/usr/bin/env python3
"""SHARD Payment System — Crypto payments with verification"""

import os
import hashlib, time, json, logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("SHARD-Payment")

# ============================================================
# ТАРИФЫ
# ============================================================
PLANS = {
    'community': {
        'name': 'Community',
        'price': 0,
        'features': [
            'Core engine',
            '5 ML models',
            'Single user',
            'Community support',
            'Basic alerts'
        ],
        'limits': {
            'alerts_per_day': 1000,
            'models': 5,
            'users': 1,
            'retention_days': 7
        }
    },
    'professional': {
        'name': 'Professional',
        'price': 299,
        'currency': 'USDT',
        'features': [
            'All 50 ML models',
            'DecisionFusion AI',
            'Telegram bot',
            'Email alerts',
            'Multi-user (up to 10)',
            '30-day data retention',
            'Priority support'
        ],
        'limits': {
            'alerts_per_day': 50000,
            'models': 50,
            'users': 10,
            'retention_days': 30
        }
    },
    'enterprise': {
        'name': 'Enterprise',
        'price': 999,
        'currency': 'USDT',
        'features': [
            'All Professional features',
            'Unlimited users',
            'Federated learning',
            'Custom integrations',
            'On-premise deployment',
            'SLA 99.9%',
            '24/7 phone support',
            'Unlimited data retention'
        ],
        'limits': {
            'alerts_per_day': 999999,
            'models': 50,
            'users': 999,
            'retention_days': 365
        }
    }
}

# ============================================================
# КРИПТО-АДРЕСА
# ============================================================
WALLETS = {
    'USDT_TRC20': os.getenv('WALLET_USDT_TRC20', 'THVqXJHryY6975tNFrqhYH5UNVipoNiDDN'),
    'USDT_ERC20': os.getenv('WALLET_USDT_ERC20', '0xD5a40E4d339668D8D9b746074a128716405Ab34c'),
    'BTC': os.getenv('WALLET_BTC', 'bc1qx8sxckvayvyz4u3cz79s9xptlnjafz8jshd0w6')
}

# ============================================================
# ХРАНИЛИЩЕ ЛИЦЕНЗИЙ
# ============================================================
LICENSES_FILE = Path('data/licenses.json')
LICENSES_FILE.parent.mkdir(exist_ok=True)

if LICENSES_FILE.exists():
    with open(LICENSES_FILE) as f:
        _licenses = json.load(f)
else:
    _licenses = {}

def _save_licenses():
    with open(LICENSES_FILE, 'w') as f:
        json.dump(_licenses, f, indent=2)


# ============================================================
# ГЕНЕРАЦИЯ ЛИЦЕНЗИОННОГО КЛЮЧА
# ============================================================
def generate_license_key(email: str, plan: str) -> str:
    """Генерирует уникальный лицензионный ключ"""
    data = f"{email}:{plan}:{time.time()}:{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
    key = "SHARD-" + hashlib.sha256(data.encode()).hexdigest()[:16].upper()
    return key


# ============================================================
# АКТИВАЦИЯ ЛИЦЕНЗИИ
# ============================================================
def activate_license(email: str, plan: str, tx_hash: str = None) -> dict:
    """
    Активирует лицензию для пользователя.
    В реальной системе — проверяет blockchain transaction.
    """
    key = generate_license_key(email, plan)
    
    _licenses[key] = {
        'email': email,
        'plan': plan,
        'activated_at': datetime.now().isoformat(),
        'expires_at': (datetime.now().replace(month=datetime.now().month + 1)).isoformat(),
        'tx_hash': tx_hash,
        'active': True,
        'features': PLANS[plan]['features'],
        'limits': PLANS[plan]['limits']
    }
    _save_licenses()
    
    logger.info(f"✅ License activated: {key} ({plan}) for {email}")
    
    return {
        'license_key': key,
        'plan': plan,
        'expires': _licenses[key]['expires_at'],
        'features': PLANS[plan]['features'],
        'limits': PLANS[plan]['limits']
    }


# ============================================================
# ПРОВЕРКА ЛИЦЕНЗИИ
# ============================================================
def verify_license(license_key: str) -> dict:
    """Проверяет действительность лицензии"""
    if license_key not in _licenses:
        return {'valid': False, 'reason': 'License not found'}
    
    lic = _licenses[license_key]
    
    if not lic.get('active', False):
        return {'valid': False, 'reason': 'License deactivated'}
    
    expires = datetime.fromisoformat(lic['expires_at'])
    if datetime.now() > expires:
        return {'valid': False, 'reason': 'License expired'}
    
    return {
        'valid': True,
        'plan': lic['plan'],
        'email': lic['email'],
        'expires': lic['expires_at'],
        'features': lic['features'],
        'limits': lic['limits']
    }


# ============================================================
# ПРОВЕРКА ДОСТУПА К ФУНКЦИЯМ
# ============================================================
def check_feature_access(license_key: str, feature: str) -> bool:
    """Проверяет доступна ли конкретная функция для этой лицензии"""
    verification = verify_license(license_key)
    if not verification['valid']:
        return False
    return feature in verification.get('features', [])


def get_user_limits(license_key: str) -> dict:
    """Возвращает лимиты для пользователя"""
    verification = verify_license(license_key)
    if not verification['valid']:
        return PLANS['community']['limits']  # Fallback на community
    return verification.get('limits', PLANS['community']['limits'])


# ============================================================
# СИМУЛЯЦИЯ ПЛАТЕЖА (для тестов)
# ============================================================
def simulate_payment(email: str, plan: str) -> dict:
    """Симулирует получение платежа (для демо)"""
    tx_hash = "DEMO-" + hashlib.md5(f"{email}{time.time()}".encode()).hexdigest()[:8]
    return activate_license(email, plan, tx_hash)


# ============================================================
# API ДЛЯ ФРОНТЕНДА
# ============================================================
def get_plans() -> dict:
    """Возвращает все тарифы"""
    result = {}
    for plan_id, plan_data in PLANS.items():
        result[plan_id] = {
            'name': plan_data['name'],
            'price': plan_data['price'],
            'currency': plan_data.get('currency', ''),
            'features': plan_data['features'],
            'limits': plan_data['limits']
        }
    return result


def get_wallets() -> dict:
    """Возвращает крипто-адреса"""
    return WALLETS


logger.info("✅ Payment system ready")

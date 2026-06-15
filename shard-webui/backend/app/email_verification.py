"""Email Verification for SHARD Registration — Using EmailService"""
import random, time, logging, sys
from pathlib import Path

logger = logging.getLogger("SHARD-Verification")
_verification_codes = {}

def generate_code() -> str:
    return str(random.randint(100000, 999999))

def send_verification_email(email: str) -> bool:
    """Отправляет код верификации на email"""
    code = generate_code()
    _verification_codes[email] = {'code': code, 'expires': time.time() + 600, 'attempts': 0}
    
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
        from modules.email_service import email_service
        
        result = email_service.send_verification_code(email, code)
        if result:
            logger.info(f"✅ Verification code sent to {email}")
            return True
        else:
            logger.error(f"❌ Failed to send code to {email}")
            return False
    except Exception as e:
        logger.error(f"❌ Error sending verification: {e}")
        return False

def verify_code(email: str, code: str) -> bool:
    """Проверяет код верификации"""
    if email not in _verification_codes:
        return False
    
    data = _verification_codes[email]
    if time.time() > data['expires'] or data['attempts'] >= 3:
        del _verification_codes[email]
        return False
    
    data['attempts'] += 1
    if data['code'] == code:
        del _verification_codes[email]
        return True
    return False

logger.info("✅ Email verification module ready")

"""Email Verification for SHARD Registration"""
import random, time, logging, sys
from pathlib import Path

logger = logging.getLogger("SHARD-Verification")
_verification_codes = {}

def generate_code() -> str:
    return str(random.randint(100000, 999999))

def send_verification_email(email: str) -> bool:
    code = generate_code()
    _verification_codes[email] = {'code': code, 'expires': time.time() + 600, 'attempts': 0}
    
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
        from modules.email_notifier import email_notifier
        
        alert = {
            'attack_type': 'Email Verification',
            'severity': 'INFO',
            'src_ip': 'system',
            'dst_ip': 'system',
            'dst_port': 0,
            'score': 0,
            'confidence': 0,
            'explanation': f'Your SHARD verification code is: {code}'
        }
        
        email_notifier.recipients = [email]
        email_notifier.send_alert(alert)
        logger.info(f"Code sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed: {e}")
        return False

def verify_code(email: str, code: str) -> bool:
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

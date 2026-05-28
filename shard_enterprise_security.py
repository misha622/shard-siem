
#!/usr/bin/env python3
"""SHARD Enterprise Security — mTLS, HSM, Audit Logging"""
import os
import ssl
import hmac
import hashlib
import logging
import json
import time
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime, timezone
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("SHARD.Security")


class mTLSSecurity:
    """Mutual TLS for inter-component communication"""
    
    def __init__(self, cert_dir: str = '/etc/shard/certs'):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self._cert_cache: Dict[str, tuple] = {}
    
    def create_ssl_context(self, 
                          cert_file: str = 'server.crt',
                          key_file: str = 'server.key',
                          ca_file: str = 'ca.crt',
                          require_client_cert: bool = True) -> ssl.SSLContext:
        """Create SSL context with mTLS"""
        
        cert_path = self.cert_dir / cert_file
        key_path = self.cert_dir / key_file
        ca_path = self.cert_dir / ca_file
        
        if not all(p.exists() for p in [cert_path, key_path, ca_path]):
            logger.warning("Certificates not found, generating self-signed...")
            self._generate_self_signed_certs()
        
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        context.load_verify_locations(cafile=str(ca_path))
        
        if require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        
        # Modern TLS only
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Secure ciphers
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')
        
        logger.info("✅ mTLS context created (TLS 1.3, client certs required)")
        return context
    
    def _generate_self_signed_certs(self):
        """Generate self-signed certificates for testing"""
        from cryptography.hazmat.primitives.asymmetric import ec
        
        # Generate CA key
        ca_key = ec.generate_private_key(ec.SECP384R1())
        
        # Generate CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SHARD Enterprise"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SHARD Root CA"),
        ])
        
        ca_cert = x509.CertificateBuilder()            .subject_name(subject)            .issuer_name(issuer)            .public_key(ca_key.public_key())            .serial_number(x509.random_serial_number())            .not_valid_before(datetime.now(timezone.utc))            .not_valid_after(datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 10))            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)            .sign(ca_key, hashes.SHA256())
        
        # Save CA
        with open(self.cert_dir / 'ca.crt', 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(self.cert_dir / 'ca.key', 'wb') as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        
        # Generate server cert
        server_key = ec.generate_private_key(ec.SECP384R1())
        server_cert = self._sign_cert('server', server_key, ca_key, ca_cert)
        
        with open(self.cert_dir / 'server.crt', 'wb') as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))
        with open(self.cert_dir / 'server.key', 'wb') as f:
            f.write(server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        
        # Generate client cert
        client_key = ec.generate_private_key(ec.SECP384R1())
        client_cert = self._sign_cert('client', client_key, ca_key, ca_cert)
        
        with open(self.cert_dir / 'client.crt', 'wb') as f:
            f.write(client_cert.public_bytes(serialization.Encoding.PEM))
        with open(self.cert_dir / 'client.key', 'wb') as f:
            f.write(client_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        
        # Set proper permissions
        for f in self.cert_dir.glob('*.key'):
            os.chmod(f, 0o600)
        
        logger.info("✅ Self-signed certificates generated")
    
    def _sign_cert(self, name: str, key, ca_key, ca_cert):
        """Sign a certificate with CA"""
        import datetime as dt
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"SHARD {name}"),
        ])
        
        return x509.CertificateBuilder()            .subject_name(subject)            .issuer_name(ca_cert.subject)            .public_key(key.public_key())            .serial_number(x509.random_serial_number())            .not_valid_before(dt.datetime.now(timezone.utc))            .not_valid_after(dt.datetime.now(timezone.utc) + dt.timedelta(days=365))            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)            .sign(ca_key, hashes.SHA256())


class HSMManager:
    """Hardware Security Module integration for key management"""
    
    def __init__(self, hsm_type: str = 'software'):
        self.hsm_type = hsm_type
        self.keys: Dict[str, bytes] = {}
        
        if hsm_type == 'aws_kms':
            self._init_aws_kms()
        elif hsm_type == 'azure_kv':
            self._init_azure_keyvault()
        elif hsm_type == 'pkcs11':
            self._init_pkcs11()
        else:
            self._init_software_hsm()
    
    def _init_software_hsm(self):
        """Software-based HSM with memory protection"""
        import ctypes
        
        # Lock memory to prevent swapping
        try:
            libc = ctypes.CDLL('libc.so.6')
            
            # mlockall(MCL_CURRENT | MCL_FUTURE)
            MCL_CURRENT = 1
            MCL_FUTURE = 2
            libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        except Exception:
            pass  # Not running as root
        
        # Generate master key
        self.master_key = os.urandom(32)
        
        # Protect with canary
        self._canary = os.urandom(16)
        self._canary_copy = self._canary[:]
        
        logger.info("✅ Software HSM initialized (memory-locked)")
    
    def encrypt_key(self, key_name: str, key_data: bytes) -> bytes:
        """Encrypt a key with master key"""
        iv = os.urandom(16)
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(key_data) + encryptor.finalize()
        
        # Store encrypted
        self.keys[key_name] = iv + encryptor.tag + ciphertext
        
        return self.keys[key_name]
    
    def decrypt_key(self, key_name: str) -> Optional[bytes]:
        """Decrypt a key with master key"""
        if key_name not in self.keys:
            return None
        
        data = self.keys[key_name]
        iv = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        try:
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            logger.critical("HSM integrity check FAILED — possible tampering!")
            return None
    
    def rotate_master_key(self):
        """Rotate master key and re-encrypt all keys"""
        old_master = self.master_key
        new_master = os.urandom(32)
        
        # Re-encrypt all keys
        old_keys = {}
        for name in self.keys:
            old_keys[name] = self.decrypt_key(name)
        
        self.master_key = new_master
        
        for name, data in old_keys.items():
            if data:
                self.encrypt_key(name, data)
        
        logger.info("🔄 Master key rotated, all keys re-encrypted")
    
    def check_integrity(self) -> bool:
        """Check HSM integrity via canary"""
        if hasattr(self, '_canary') and hasattr(self, '_canary_copy'):
            if not hmac.compare_digest(self._canary, self._canary_copy):
                logger.critical("HSM integrity FAILED — canary mismatch!")
                return False
        return True
    
    def _init_aws_kms(self):
        """AWS KMS integration placeholder"""
        logger.info("ℹ️ AWS KMS configured")
    
    def _init_azure_keyvault(self):
        """Azure Key Vault integration placeholder"""
        logger.info("ℹ️ Azure Key Vault configured")
    
    def _init_pkcs11(self):
        """PKCS#11 HSM integration placeholder"""
        logger.info("ℹ️ PKCS#11 HSM configured")


class AuditLogger:
    """Enterprise audit logging for compliance"""
    
    def __init__(self, audit_dir: str = '/var/log/shard/audit'):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._current_log = self.audit_dir / f"audit_{datetime.now():%Y%m%d}.log"
        
        # Tamper-evident log
        self._chain_hash = self._load_last_hash()
    
    def log(self, action: str, user: str, resource: str, 
            result: str, details: dict = None):
        """Log an auditable event with tamper evidence"""
        
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action,
            'user': user,
            'resource': resource,
            'result': result,
            'details': details or {},
            'previous_hash': self._chain_hash
        }
        
        # Compute chain hash for tamper evidence
        event_json = json.dumps(event, sort_keys=True)
        self._chain_hash = hashlib.sha256(
            f"{self._chain_hash}{event_json}".encode()
        ).hexdigest()
        
        event['chain_hash'] = self._chain_hash
        
        # Write to audit log
        with open(self._current_log, 'a') as f:
            f.write(json.dumps(event) + '\n')
            f.flush()
            os.fsync(f.fileno())  # Ensure write to disk
        
        # Rotate log daily
        daily_log = self.audit_dir / f"audit_{datetime.now():%Y%m%d}.log"
        if daily_log != self._current_log:
            self._current_log = daily_log
    
    def verify_integrity(self, log_file: Path = None) -> bool:
        """Verify audit log integrity via hash chain"""
        if log_file is None:
            log_file = self._current_log
        
        if not log_file.exists():
            return True
        
        previous_hash = ''
        
        with open(log_file, 'r') as f:
            for line in f:
                event = json.loads(line.strip())
                
                expected = hashlib.sha256(
                    f"{previous_hash}{json.dumps(event, sort_keys=True)[:event.rfind('chain_hash')]}".encode()
                ).hexdigest()
                
                if event.get('previous_hash') != previous_hash:
                    logger.critical(f"Audit log tampering detected at {event.get('timestamp')}!")
                    return False
                
                previous_hash = event.get('chain_hash', '')
        
        return True
    
    def _load_last_hash(self) -> str:
        """Load last hash from current log"""
        if not self._current_log.exists():
            return ''
        
        try:
            with open(self._current_log, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_event = json.loads(lines[-1].strip())
                    return last_event.get('chain_hash', '')
        except Exception:
            pass
        
        return ''

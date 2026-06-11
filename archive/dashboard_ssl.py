#!/usr/bin/env python3
"""Dashboard с SSL/TLS через self-signed сертификат (для staging) или Let's Encrypt"""
import ssl, os
from pathlib import Path

def create_self_signed_cert(cert_dir: str = "certs"):
    """Создаёт self-signed сертификат для тестирования"""
    Path(cert_dir).mkdir(exist_ok=True)
    cert_path = os.path.join(cert_dir, "shard_dashboard.pem")
    key_path = os.path.join(cert_dir, "shard_dashboard_key.pem")
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    
    from OpenSSL import crypto
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    os.chmod(key_path, 0o600)
    return cert_path, key_path

def wrap_socket_with_ssl(sock, cert_path=None, key_path=None):
    """Оборачивает сокет в SSL/TLS"""
    if not cert_path:
        cert_path, key_path = create_self_signed_cert()
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')
    return context.wrap_socket(sock, server_side=True)

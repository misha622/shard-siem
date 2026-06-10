#!/usr/bin/env python3
"""
SHARD Defense Model Trainer v4
Единый скрипт обучения: sklearn TfidfVectorizer + XGBoost
Заменяет: shard_codegen_trainer.py + shard_codegen_v3_improved.py
"""

import pickle
import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-Defense-Trainer")


ATTACK_TYPES = [
    'SQL Injection', 'Brute Force', 'DDoS', 'Port Scan', 'C2 Beacon',
    'DNS Tunnel', 'XSS', 'Lateral Movement', 'Data Exfiltration',
    'Botnet', 'Ransomware', 'Phishing', 'Zero-Day'
]

DEFENSE_RULES = {
    'SQL Injection': [
        'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
        'SecRule REQUEST_URI "@rx union.*select" "id:1001,phase:2,deny,status:403"',
        'iptables -A INPUT -p tcp --dport {port} -m string --string "UNION SELECT" --algo bm -j DROP',
    ],
    'Brute Force': [
        'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
        'iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP',
        'iptables -A INPUT -s {ip} -j LOG --log-prefix "BRUTE-FORCE: "',
    ],
    'DDoS': [
        'iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT',
        'iptables -A INPUT -p tcp --syn -j DROP',
        'echo 1 > /proc/sys/net/ipv4/tcp_syncookies',
        'sysctl -w net.ipv4.tcp_max_syn_backlog=2048',
    ],
    'Port Scan': [
        'iptables -A INPUT -s {ip} -j DROP',
        'iptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP',
        'iptables -A INPUT -m recent --name portscan --set -j DROP',
    ],
    'C2 Beacon': [
        'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
        'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP',
        'iptables -A FORWARD -s {ip} -j DROP',
        'iptables -A INPUT -s {ip} -j LOG --log-prefix "C2-BLOCKED: "',
    ],
    'DNS Tunnel': [
        'iptables -A INPUT -s {ip} -p udp --dport 53 -m length --length 512:65535 -j DROP',
        'iptables -A INPUT -s {ip} -p udp --dport 53 -m string --hex-string "|0000|" --algo bm -j DROP',
    ],
    'XSS': [
        'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
        'SecRule REQUEST_URI "@rx <script" "id:2001,phase:2,deny,status:403"',
        'SecRule REQUEST_URI "@rx javascript:" "id:2002,phase:2,deny,status:403"',
    ],
    'Lateral Movement': [
        'iptables -A INPUT -s {ip} -p tcp --dport 445 -j DROP',
        'iptables -A INPUT -s {ip} -p tcp --dport 139 -j DROP',
        'iptables -A INPUT -s {ip} -p tcp --dport 135 -j DROP',
        'iptables -A FORWARD -s {ip} -j DROP',
    ],
    'Data Exfiltration': [
        'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP',
        'iptables -A OUTPUT -d {ip} -j DROP',
        'iptables -A OUTPUT -d {ip} -j LOG --log-prefix "EXFIL-BLOCKED: "',
    ],
    'Botnet': [
        'iptables -A INPUT -s {ip} -j DROP',
        'iptables -A OUTPUT -d {ip} -j DROP',
        'iptables -A FORWARD -s {ip} -j DROP',
        'iptables -A FORWARD -d {ip} -j DROP',
    ],
    'Ransomware': [
        'iptables -A INPUT -s {ip} -j DROP',
        'iptables -A OUTPUT -d {ip} -j DROP',
        'iptables -A OUTPUT -p tcp --dport 445 -j DROP',
        'iptables -A FORWARD -s {ip} -j DROP',
        'iptables -A INPUT -s {ip} -j LOG --log-prefix "RANSOMWARE: "',
    ],
    'Phishing': [
        'iptables -A INPUT -s {ip} -p tcp --dport 80 -j DROP',
        'iptables -A INPUT -s {ip} -p tcp --dport 443 -j DROP',
        'iptables -A INPUT -s {ip} -j DROP',
    ],
    'Zero-Day': [
        'iptables -A INPUT -s {ip} -j DROP',
        'iptables -A OUTPUT -d {ip} -j DROP',
        'iptables -A FORWARD -s {ip} -j DROP',
        'iptables -A INPUT -s {ip} -j LOG --log-prefix "ZERO-DAY: "',
        'tcpdump -i any -w /tmp/shard_zeroday_$(date +%s).pcap host {ip} &',
    ],
}

IPS = [
    '185.142.53.101', '45.155.205.233', '194.61.23.45', '89.248.163.1',
    '103.145.12.67', '185.165.29.82', '45.134.26.99', '203.0.113.100',
    '198.51.100.200', '192.168.1.50', '10.0.0.50', '172.16.0.25',
    '91.240.118.22', '77.247.181.162', '5.188.87.50', '141.98.81.100',
    '45.227.255.201', '185.220.101.45', '23.129.64.210', '107.174.55.99'
]

PORTS = [
    22, 80, 443, 3306, 5432, 6379, 8080, 8443, 4444, 5555,
    9090, 21, 25, 53, 135, 139, 445, 3389, 5985, 8888
]

ATTACK_VARIATIONS = {
    'SQL Injection': [
        'SQL Injection from {ip} on port {port}',
        'SQLi attack detected from {ip} targeting port {port}',
        'MySQL injection attempt from {ip}:{port}',
        'UNION SELECT injection from {ip}',
        'Blind SQL injection from {ip} on port {port}',
        'Error-based SQLi from {ip}',
        'Time-based blind SQLi from {ip}:{port}',
        'Out-of-band SQL injection from {ip}',
        'Second-order SQL injection detected from {ip}',
        'PostgreSQL injection from {ip} on port {port}',
    ],
    'Brute Force': [
        'Brute Force from {ip} on port {port}',
        'SSH brute force attack from {ip}:{port}',
        'Multiple failed logins from {ip}',
        'Password guessing attack from {ip}',
        'Dictionary attack from {ip} on port {port}',
        'Credential stuffing from {ip}',
        'FTP brute force from {ip}:{port}',
        'RDP brute force attempt from {ip}',
        'Telnet brute force from {ip} on port {port}',
        'Hydra brute force from {ip}',
    ],
    'DDoS': [
        'DDoS from {ip} on port {port}',
        'SYN flood DDoS from {ip}',
        'Distributed denial of service from {ip}',
        'UDP flood from {ip} on port {port}',
        'HTTP flood DDoS from {ip}:{port}',
        'ICMP flood from {ip}',
        'DNS amplification DDoS from {ip}',
        'NTP amplification attack from {ip}',
        'Slowloris attack from {ip} on port {port}',
        'Memcached amplification from {ip}',
    ],
    'Port Scan': [
        'Port Scan from {ip} on port {port}',
        'Network scan detected from {ip}',
        'Sequential port scanning from {ip}',
        'Nmap scan from {ip}',
        'Service version probe from {ip}:{port}',
        'TCP SYN scan from {ip}',
        'TCP connect scan from {ip}',
        'UDP port scan from {ip}',
        'Aggressive scanning from {ip} on port {port}',
        'Masscan detected from {ip}',
    ],
    'C2 Beacon': [
        'C2 Beacon from {ip} on port {port}',
        'Command and control communication from {ip}',
        'CobaltStrike beacon from {ip}:{port}',
        'Periodic HTTPS beacon to {ip}',
        'Meterpreter reverse shell beacon from {ip}',
        'Empire C2 beacon from {ip}:{port}',
        'Sliver C2 communication from {ip}',
        'DNS beaconing to {ip}',
        'ICMP C2 tunnel from {ip}',
        'WebSocket C2 channel to {ip}:{port}',
    ],
    'DNS Tunnel': [
        'DNS Tunnel from {ip} on port 53',
        'DNS exfiltration detected from {ip}',
        'Suspicious DNS queries from {ip}',
        'DNS tunneling via {ip}',
        'DNS over HTTPS tunnel from {ip}',
        'Iodine DNS tunnel from {ip}',
        'DNScat2 tunnel detected from {ip}',
        'High-entropy DNS queries from {ip}',
        'TXT record tunneling from {ip}',
        'DNS C2 beaconing from {ip}',
    ],
    'XSS': [
        'XSS from {ip} on port {port}',
        'Cross-site scripting from {ip}',
        'Reflected XSS attack from {ip}',
        'Stored XSS from {ip}:{port}',
        'DOM-based XSS from {ip}',
        'Blind XSS payload from {ip}',
        'Angular XSS from {ip} on port {port}',
        'jQuery XSS injection from {ip}',
        'Polyglot XSS from {ip}',
        'Mutation XSS from {ip}:{port}',
    ],
    'Lateral Movement': [
        'Lateral Movement from {ip} on port {port}',
        'SMB lateral movement from {ip}',
        'Internal network spread from {ip}',
        'Pass-the-hash from {ip} on port {port}',
        'WMI lateral movement from {ip}',
        'PsExec lateral movement from {ip}',
        'RDP lateral movement from {ip}:{port}',
        'WinRM lateral movement from {ip}',
        'Scheduled task lateral movement from {ip}',
        'Service creation lateral movement from {ip}',
    ],
    'Data Exfiltration': [
        'Data Exfiltration from {ip} on port {port}',
        'Large outbound transfer to {ip}',
        'Suspicious data upload to {ip}',
        'Confidential data leak to {ip}:{port}',
        'Database dump exfiltration to {ip}',
        'Archive exfiltration to {ip} on port {port}',
        'Cloud storage exfiltration via {ip}',
        'Email attachment exfiltration to {ip}',
        'FTP exfiltration to {ip}:{port}',
        'Encrypted exfiltration channel to {ip}',
    ],
    'Botnet': [
        'Botnet from {ip} on port {port}',
        'Botnet C2 communication from {ip}',
        'Infected host beaconing to {ip}',
        'Mirai botnet from {ip}:{port}',
        'Gafgyt botnet from {ip}',
        'Mozi botnet communication from {ip}',
        'Emotet botnet from {ip}:{port}',
        'Trickbot botnet C2 from {ip}',
        'Qakbot botnet from {ip}',
        'Infected IoT botnet from {ip}:{port}',
    ],
    'Ransomware': [
        'Ransomware from {ip} on port {port}',
        'Ransomware encryption activity from {ip}',
        'File encryption detected from {ip}',
        'WannaCry ransomware from {ip}',
        'Ryuk ransomware from {ip}:{port}',
        'LockBit ransomware from {ip}',
        'Conti ransomware from {ip}',
        'Revil ransomware from {ip}:{port}',
        'BlackCat ransomware from {ip}',
        'Ransom note creation from {ip}',
    ],
    'Phishing': [
        'Phishing from {ip} on port {port}',
        'Phishing page hosted at {ip}',
        'Credential harvesting from {ip}',
        'Spear phishing from {ip}:{port}',
        'Clone phishing from {ip}',
        'Whaling phishing from {ip}',
        'Fake login page at {ip}:{port}',
        'Business email compromise from {ip}',
        'Social engineering from {ip}',
        'Malicious redirect to {ip}',
    ],
    'Zero-Day': [
        'Zero-Day from {ip} on port {port}',
        'Unknown attack pattern from {ip}',
        'New exploit detected from {ip}',
        'Suspicious unknown traffic from {ip}',
        'Novel attack technique from {ip}:{port}',
        'Unclassified threat from {ip}',
        'Zero-day exploit attempt from {ip}',
        'Previously unseen attack from {ip}:{port}',
        'Anomalous payload from {ip}',
        'Emerging threat from {ip} on port {port}',
    ],
}


def create_dataset() -> List[Dict]:
    samples = []

    for attack_type, variations in ATTACK_VARIATIONS.items():
        for ip in IPS:
            for port in PORTS[:5]:
                for variant in variations[:3]:
                    attack_text = variant.format(ip=ip, port=port)
                    samples.append({
                        'text': attack_text,
                        'label': attack_type,
                        'ip': ip,
                        'port': port,
                    })

    np.random.seed(42)
    np.random.shuffle(samples)

    logger.info(f"Датасет создан: {len(samples)} сэмплов, {len(ATTACK_TYPES)} классов")
    logger.info(f"Распределение классов:")
    for atype in ATTACK_TYPES:
        count = sum(1 for s in samples if s['label'] == atype)
        logger.info(f"  {atype}: {count}")

    return samples


def train_model(samples: List[Dict]) -> Tuple:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import LabelEncoder
    import xgboost as xgb

    texts = [s['text'] for s in samples]
    labels = [s['label'] for s in samples]

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(labels)

    logger.info("TF-IDF векторизация...")
    vectorizer = TfidfVectorizer(
        max_features=500,
        ngram_range=(1, 3),
        analyzer='word',
        stop_words=None,
        lowercase=True,
        sublinear_tf=True,
    )
    X = vectorizer.fit_transform(texts)

    logger.info(f"Матрица признаков: {X.shape}")
    logger.info(f"Словарь: {len(vectorizer.vocabulary_)} токенов")

    logger.info("Обучение XGBoost...")
    classifier = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=10,
        learning_rate=0.05,
        objective='multi:softprob',
        num_class=len(ATTACK_TYPES),
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

    classifier.fit(X, y)

    train_preds = classifier.predict(X)
    train_acc = (train_preds == y).mean()
    logger.info(f"Точность на тренировочных данных: {train_acc:.2%}")

    train_proba = classifier.predict_proba(X)
    avg_confidence = np.max(train_proba, axis=1).mean()
    logger.info(f"Средняя уверенность: {avg_confidence:.2%}")

    return vectorizer, classifier, label_encoder


def test_model(vectorizer, classifier, label_encoder) -> float:
    test_cases = [
        ("SQL Injection from 45.33.32.156 on port 3306", "SQL Injection"),
        ("SSH brute force attack from 91.240.118.22:22", "Brute Force"),
        ("SYN flood DDoS from 203.0.113.42", "DDoS"),
        ("Nmap scan detected from 77.247.181.162", "Port Scan"),
        ("CobaltStrike beacon from 5.188.87.50:4444", "C2 Beacon"),
        ("DNS exfiltration via iodine tunnel from 141.98.81.100", "DNS Tunnel"),
        ("Reflected XSS payload from 45.227.255.201 on port 443", "XSS"),
        ("SMB lateral movement attempt from 10.0.0.99", "Lateral Movement"),
        ("Large encrypted upload to 185.220.101.45:443", "Data Exfiltration"),
        ("Mirai botnet C2 from 23.129.64.210:5555", "Botnet"),
        ("File encryption ransomware from 107.174.55.99", "Ransomware"),
        ("Credential harvesting phishing page at 192.168.1.200", "Phishing"),
        ("Zero-day exploit from 198.51.100.99 on port 9090", "Zero-Day"),
        ("Unknown attack pattern from 203.0.113.99:8080", "Zero-Day"),
        ("FTP brute force from 45.155.205.233:21", "Brute Force"),
        ("HTTP flood DDoS from 89.248.163.1 on port 80", "DDoS"),
        ("WannaCry ransomware spreading from 10.0.0.50", "Ransomware"),
        ("DNS tunnel high-entropy queries from 172.16.0.25", "DNS Tunnel"),
    ]

    correct = 0
    results = []

    print("\n" + "=" * 70)
    print("🧪 ТЕСТИРОВАНИЕ МОДЕЛИ")
    print("=" * 70)

    for text, expected in test_cases:
        X = vectorizer.transform([text])
        proba = classifier.predict_proba(X)[0]
        predicted_idx = np.argmax(proba)
        predicted = label_encoder.inverse_transform([predicted_idx])[0]
        confidence = proba[predicted_idx]

        is_correct = (predicted == expected)
        if is_correct:
            correct += 1

        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', text)
        ip = ip_match.group(0) if ip_match else '0.0.0.0'
        port_match = re.search(r':(\d+)|port (\d+)', text)
        port = port_match.group(1) or port_match.group(2) if port_match else '80'

        status = "✅" if is_correct else "❌"
        print(f"\n{status} Текст: {text}")
        print(f"   Ожидалось: {expected} → Предсказано: {predicted} ({confidence:.0%})")

        if predicted in DEFENSE_RULES:
            rules = DEFENSE_RULES[predicted]
            defense_preview = rules[0].format(ip=ip, port=port)
            print(f"   Код защиты: {defense_preview[:80]}...")
            if confidence < 0.5:
                print(f"   ⚠️ Низкая уверенность — возможен fallback на keyword matching")

    accuracy = correct / len(test_cases)
    print(f"\n{'=' * 70}")
    print(f"Точность: {correct}/{len(test_cases)} ({accuracy:.0%})")
    print(f"{'=' * 70}")

    return accuracy


def save_model(vectorizer, classifier, label_encoder, path: str = './models/defense_classifier_v3.pkl'):
    Path(path).parent.mkdir(exist_ok=True)

    model_data = {
        'vectorizer': vectorizer,
        'classifier': classifier,
        'label_encoder': label_encoder,
        'attack_types': ATTACK_TYPES,
        'defense_rules': DEFENSE_RULES,
        'model_version': 'v4.0',
        'model_type': 'TfidfVectorizer+XGBoost',
        'feature_count': len(vectorizer.vocabulary_) if hasattr(vectorizer, 'vocabulary_') else 0,
        'num_classes': len(ATTACK_TYPES),
    }

    with open(path, 'wb') as f:
        pickle.dump(model_data, f, protocol=pickle.HIGHEST_PROTOCOL)

    file_size = Path(path).stat().st_size
    logger.info(f"✅ Модель сохранена: {path} ({file_size / 1024:.1f} KB)")


def print_pipeline_integration_guide():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  ИНТЕГРАЦИЯ С DEFENSE PIPELINE V2                                   ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Модель сохранена в models/defense_classifier_v3.pkl                ║
║                                                                      ║
║  DefenseModelLoader уже загружает этот файл.                        ║
║  Нужно заменить метод predict() в shard_defense_pipeline_v2.py:     ║
║                                                                      ║
║  def predict(self, text: str) -> Tuple[str, float]:                  ║
║
║      if self._ml_loaded:                                             ║
║          try:                                                        ║
║              X = self.vectorizer.transform([text])                   ║
║              proba = self.classifier.predict_proba(X)[0]             ║
║              idx = proba.argmax()                                    ║
║              conf = proba[idx]                                       ║
║              if conf > 0.4:                                          ║
║                  return self.label_encoder.inverse_transform(        ║
║                      [idx])[0], conf                                 ║
║          except Exception:                                           ║
║              pass                                                    ║
║
║      return self._keyword_predict(text)                              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
""")


def main():
    print("=" * 70)
    print("🧠 SHARD DEFENSE MODEL TRAINER v4.0")
    print("   sklearn TfidfVectorizer + XGBoost")
    print("=" * 70)

    print("\n📊 Шаг 1/4: Генерация датасета...")
    samples = create_dataset()

    print(f"\n🔄 Шаг 2/4: Обучение модели...")
    vectorizer, classifier, label_encoder = train_model(samples)

    print(f"\n🧪 Шаг 3/4: Тестирование модели...")
    accuracy = test_model(vectorizer, classifier, label_encoder)

    print(f"\n💾 Шаг 4/4: Сохранение модели...")
    save_model(vectorizer, classifier, label_encoder)

    print_pipeline_integration_guide()

    print(f"\n{'=' * 70}")
    print(f"✅ ОБУЧЕНИЕ ЗАВЕРШЕНО!")
    print(f"   Точность: {accuracy:.0%}")
    print(f"   Модель: models/defense_classifier_v3.pkl")
    print(f"   Классов: {len(ATTACK_TYPES)}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
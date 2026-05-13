#!/usr/bin/env python3
"""
SHARD CodeGen v3 — Улучшенная модель с TF-IDF + n-gram + 500 сэмплов
"""

import json, time, pickle, logging, re
from pathlib import Path
from typing import Dict, List, Tuple, Tuple
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SHARD-CodeGen-v3")


class SimpleTFIDF:
    
    def __init__(self, max_features: int = 200):
        self.max_features = max_features
        self.vocabulary: Dict[str, int] = {}
        self.idf: np.ndarray = None
        
    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        tokens = re.findall(r'[a-z0-9]+', text)
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens)-1)]
        trigrams = [f"{tokens[i]}_{tokens[i+1]}_{tokens[i+2]}" for i in range(len(tokens)-2)]
        return tokens + bigrams + trigrams
    
    def fit(self, texts: List[str]):
        df = {}
        for text in texts:
            tokens = set(self._tokenize(text))
            for token in tokens:
                df[token] = df.get(token, 0) + 1
        
        sorted_tokens = sorted(df.items(), key=lambda x: -x[1])[:self.max_features]
        self.vocabulary = {token: i for i, (token, _) in enumerate(sorted_tokens)}
        
        n_docs = len(texts)
        self.idf = np.zeros(len(self.vocabulary))
        for token, idx in self.vocabulary.items():
            self.idf[idx] = np.log((n_docs + 1) / (df.get(token, 1) + 1)) + 1
    
    def transform(self, text: str) -> np.ndarray:
        tokens = self._tokenize(text)
        tf = np.zeros(len(self.vocabulary))
        
        for token in tokens:
            if token in self.vocabulary:
                tf[self.vocabulary[token]] += 1
        
        if tf.sum() > 0:
            tf = tf / tf.sum()
        
        return tf * self.idf
    
    def fit_transform(self, texts: List[str]) -> np.ndarray:
        self.fit(texts)
        return np.array([self.transform(t) for t in texts])


def create_large_dataset() -> List[Dict]:
    
    defense_rules = {
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
    
    ips = [
        '185.142.53.101', '45.155.205.233', '194.61.23.45', '89.248.163.1',
        '103.145.12.67', '45.134.26.99', '203.0.113.50', '198.51.100.200',
        '192.168.1.100', '10.0.0.50'
    ]
    
    ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 4444, 5555, 9090]
    
    samples = []
    
    variations = {
        'SQL Injection': [
            'SQL Injection from {ip} on port {port}',
            'SQLi attack detected from {ip} targeting port {port}',
            'MySQL injection attempt from {ip}:{port}',
            'UNION SELECT injection from {ip}',
        ],
        'Brute Force': [
            'Brute Force from {ip} on port {port}',
            'SSH brute force attack from {ip}:{port}',
            'Multiple failed logins from {ip}',
            'Password guessing attack from {ip}',
        ],
        'DDoS': [
            'DDoS from {ip} on port {port}',
            'SYN flood DDoS from {ip}',
            'Distributed denial of service from {ip}',
            'UDP flood from {ip} on port {port}',
        ],
        'Port Scan': [
            'Port Scan from {ip} on port {port}',
            'Network scan detected from {ip}',
            'Sequential port scanning from {ip}',
            'Nmap scan from {ip}',
        ],
        'C2 Beacon': [
            'C2 Beacon from {ip} on port {port}',
            'Command and control communication from {ip}',
            'CobaltStrike beacon from {ip}:{port}',
            'Periodic HTTPS beacon to {ip}',
        ],
        'DNS Tunnel': [
            'DNS Tunnel from {ip} on port 53',
            'DNS exfiltration detected from {ip}',
            'Suspicious DNS queries from {ip}',
            'DNS tunneling via {ip}',
        ],
        'XSS': [
            'XSS from {ip} on port {port}',
            'Cross-site scripting from {ip}',
            'Reflected XSS attack from {ip}',
        ],
        'Lateral Movement': [
            'Lateral Movement from {ip} on port {port}',
            'SMB lateral movement from {ip}',
            'Internal network spread from {ip}',
        ],
        'Data Exfiltration': [
            'Data Exfiltration from {ip} on port {port}',
            'Large outbound transfer to {ip}',
            'Suspicious data upload to {ip}',
        ],
        'Botnet': [
            'Botnet from {ip} on port {port}',
            'Botnet C2 communication from {ip}',
            'Infected host beaconing to {ip}',
        ],
        'Ransomware': [
            'Ransomware from {ip} on port {port}',
            'Ransomware encryption activity from {ip}',
            'File encryption detected from {ip}',
        ],
        'Phishing': [
            'Phishing from {ip} on port {port}',
            'Phishing page hosted at {ip}',
            'Credential harvesting from {ip}',
        ],
        'Zero-Day': [
            'Zero-Day from {ip} on port {port}',
            'Unknown attack pattern from {ip}',
            'New exploit detected from {ip}',
            'Suspicious unknown traffic from {ip}',
        ],
    }
    
    for attack_type, rules in defense_rules.items():
        variants = variations.get(attack_type, [attack_type + ' from {ip} on port {port}'])
        
        for ip in ips:
            for port in ports[:5]:
                for variant in variants[:2]:
                    attack = variant.format(ip=ip, port=port)
                    defense = '\n'.join(rule.format(ip=ip, port=port) for rule in rules)
                    samples.append({'attack': attack, 'defense': defense})
    
    logger.info(f"Датасет создан: {len(samples)} сэмплов, {len(defense_rules)} типов атак")
    return samples


class ImprovedDefenseClassifier:
    
    def __init__(self):
        self.attack_types = []
        self.weights = None
        self.bias = None
        self.vectorizer = SimpleTFIDF(max_features=200)
        self.trained = False
        self.train_losses = []
    
    def train(self, samples: List[Dict], epochs: int = 200, lr: float = 0.01):
        attack_texts = [s['attack'] for s in samples]
        self.attack_types = sorted(set(
            ' '.join(s['attack'].split()[:2]) for s in samples
        ))
        
        logger.info("TF-IDF векторизация...")
        X = self.vectorizer.fit_transform(attack_texts)
        logger.info(f"Размерность: {X.shape}")
        
        n_features = X.shape[1]
        n_classes = len(self.attack_types)
        
        y = np.zeros((len(samples), n_classes))
        for i, s in enumerate(samples):
            attack_prefix = ' '.join(s['attack'].split()[:2])
            for j, atype in enumerate(self.attack_types):
                if attack_prefix in atype or atype in attack_prefix:
                    y[i, j] = 1.0
        
        self.weights = np.random.randn(n_features, n_classes) * np.sqrt(2.0 / n_features)
        self.bias = np.zeros(n_classes)
        
        batch_size = 32
        n_batches = (len(samples) + batch_size - 1) // batch_size
        
        for epoch in range(epochs):
            indices = np.random.permutation(len(samples))
            
            epoch_loss = 0.0
            
            for batch_idx in range(n_batches):
                start = batch_idx * batch_size
                end = min(start + batch_size, len(samples))
                batch_indices = indices[start:end]
                
                X_batch = X[batch_indices]
                y_batch = y[batch_indices]
                
                logits = np.dot(X_batch, self.weights) + self.bias
                
                logits_max = np.max(logits, axis=1, keepdims=True)
                exp_logits = np.exp(logits - logits_max)
                probs = exp_logits / np.sum(exp_logits, axis=1, keepdims=True)
                
                loss = -np.mean(np.sum(y_batch * np.log(probs + 1e-8), axis=1))
                epoch_loss += loss
                
                d_logits = (probs - y_batch) / len(batch_indices)
                d_weights = np.dot(X_batch.T, d_logits)
                d_bias = np.sum(d_logits, axis=0)
                
                d_weights += 0.0001 * self.weights
                
                self.weights -= lr * d_weights
                self.bias -= lr * d_bias
            
            avg_loss = epoch_loss / n_batches
            self.train_losses.append(avg_loss)
            
            if epoch % 40 == 0:
                logits = np.dot(X, self.weights) + self.bias
                preds = np.argmax(logits, axis=1)
                true_labels = np.argmax(y, axis=1)
                acc = np.mean(preds == true_labels)
                logger.info(f"Epoch {epoch}: loss={avg_loss:.4f}, accuracy={acc:.2%}")
        
        self.trained = True
        logger.info(f"✅ Обучение завершено!")
    
    def predict(self, attack_text: str) -> Tuple[str, float]:
        X = self.vectorizer.transform(attack_text).reshape(1, -1)
        logits = np.dot(X, self.weights) + self.bias
        
        logits_max = np.max(logits)
        exp_logits = np.exp(logits - logits_max)
        probs = exp_logits / np.sum(exp_logits)
        
        predicted_idx = np.argmax(probs)
        confidence = float(probs[0][predicted_idx]) if probs.ndim > 1 else float(probs[predicted_idx])
        
        return self.attack_types[predicted_idx], confidence
    
    def save(self, path: str = './models/defense_classifier_v3.pkl'):
        Path(path).parent.mkdir(exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'attack_types': self.attack_types,
                'weights': self.weights,
                'bias': self.bias,
                'vectorizer': self.vectorizer,
                'trained': self.trained,
                'train_losses': self.train_losses,
            }, f)
        logger.info(f"✅ Модель сохранена: {path}")


def main():
    print("=" * 60)
    print("🧠 SHARD CODE DEFENSE v3 — TF-IDF + n-gram")
    print("=" * 60)
    
    samples = create_large_dataset()
    
    model = ImprovedDefenseClassifier()
    model.train(samples, epochs=200, lr=0.02)
    
    model.save('./models/defense_classifier_v3.pkl')
    
    print("\n" + "=" * 60)
    print("🧪 ТЕСТ ГЕНЕРАЦИИ ЗАЩИТЫ")
    print("=" * 60)
    
    defense_rules = {
        'SQL Injection': 'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\nSecRule REQUEST_URI "@rx union.*select" "id:1001,phase:2,deny,status:403"',
        'Brute Force': 'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\niptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP',
        'DDoS': 'iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT\niptables -A INPUT -p tcp --syn -j DROP\necho 1 > /proc/sys/net/ipv4/tcp_syncookies',
        'Port Scan': 'iptables -A INPUT -s {ip} -j DROP\niptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP',
        'C2 Beacon': 'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\niptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP',
        'DNS Tunnel': 'iptables -A INPUT -s {ip} -p udp --dport 53 -m length --length 512:65535 -j DROP',
        'Botnet': 'iptables -A INPUT -s {ip} -j DROP\niptables -A OUTPUT -d {ip} -j DROP',
        'Zero-Day': 'iptables -A INPUT -s {ip} -j DROP\niptables -A OUTPUT -d {ip} -j DROP\ntcpdump -i any -w /tmp/zeroday.pcap host {ip} &',
    }
    
    tests = [
        ("SQL Injection from 185.142.53.101 on port 80", "SQL Injection"),
        ("SSH brute force attack from 45.155.205.233:22", "Brute Force"),
        ("SYN flood DDoS from 194.61.23.45", "DDoS"),
        ("Nmap scan from 89.248.163.1", "Port Scan"),
        ("C2 Beacon from 103.145.12.67 on port 4444", "C2 Beacon"),
        ("DNS exfiltration detected from 45.134.26.99", "DNS Tunnel"),
        ("Unknown attack pattern from 203.0.113.50 on port 9090", "Zero-Day"),
    ]
    
    correct = 0
    for attack, expected in tests:
        predicted, confidence = model.predict(attack)
        is_correct = expected in predicted or predicted in expected
        correct += int(is_correct)
        
        ip = [w for w in attack.split() if '.' in w and any(c.isdigit() for c in w)][0] if '.' in attack else '0.0.0.0'
        port = [w for w in attack.replace(':', ' ').split() if w.isdigit()][-1] if any(w.isdigit() for w in attack.replace(':', ' ').split()) else '80'
        
        print(f"\n{'✅' if is_correct else '❌'} Атака: {attack}")
        print(f"   Ожидалось: {expected}")
        print(f"   Определено: {predicted} ({confidence:.0%})")
        if predicted in defense_rules or any(p in defense_rules for p in defense_rules):
            matched = None
            for k in defense_rules:
                if k in predicted or predicted in k:
                    matched = k
                    break
            if matched:
                print(f"   Защита:\n{defense_rules[matched].format(ip=ip, port=port)[:100]}...")
    
    print(f"\n{'='*60}")
    print(f"Точность: {correct}/{len(tests)} ({correct/len(tests):.0%})")
    print(f"Модель сохранена: models/defense_classifier_v3.pkl")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

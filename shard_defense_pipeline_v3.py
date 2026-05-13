#!/usr/bin/env python3
"""
SHARD Defense Pipeline v3 — Seq2Seq Transformer генератор защитного кода
Заменяет шаблоны ModelCodeGen на нейросеть (5.3M параметров)
"""

import pickle
import time
import threading
import logging
import re
import torch
import torch.nn as nn
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SHARD-Pipeline-v3")

# Telegram/Slack/Discord нотификатор
try:
    from shard_notifier import get_notifier
    _notifier = get_notifier()
except:
    _notifier = None

# Telegram/Slack/Discord нотификатор
try:
    from shard_notifier import get_notifier
    _notifier = get_notifier()
except:
    _notifier = None

# Импорт RL агента
try:
    from shard_rl_integration import RLDefenseAgent
    RL_AVAILABLE = True
except ImportError:
    RL_AVAILABLE = False
    RLDefenseAgent = None


# ============================================================
# Seq2Seq ГЕНЕРАТОР (из train_seq2seq_defense_v2.py)
# ============================================================

class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=200):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len).float().unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-np.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer('pe', pe)
    
    def forward(self, x):
        return x + self.pe[:x.size(1)]


class Seq2SeqTransformer(nn.Module):
    def __init__(self, vocab_size, embed_dim=256, num_heads=8, num_layers=4, hidden_dim=512, dropout=0.15, max_len=120):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_encoder = PositionalEncoding(embed_dim, max_len)
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads, dim_feedforward=hidden_dim,
            dropout=dropout, activation='relu', batch_first=True
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        decoder_layer = nn.TransformerDecoderLayer(
            d_model=embed_dim, nhead=num_heads, dim_feedforward=hidden_dim,
            dropout=dropout, activation='relu', batch_first=True
        )
        self.decoder = nn.TransformerDecoder(decoder_layer, num_layers=num_layers)
        
        self.output_proj = nn.Linear(embed_dim, vocab_size)
        self.dropout = nn.Dropout(dropout)
        self.max_len = max_len
        self.vocab_size = vocab_size
        
    def forward(self, src, tgt, tgt_mask=None):
        src_emb = self.dropout(self.pos_encoder(self.embedding(src)))
        memory = self.encoder(src_emb, src_key_padding_mask=(src == 0))
        tgt_emb = self.dropout(self.pos_encoder(self.embedding(tgt)))
        if tgt_mask is None:
            tgt_mask = nn.Transformer.generate_square_subsequent_mask(tgt.size(1)).to(tgt.device)
        output = self.decoder(tgt_emb, memory, tgt_mask=tgt_mask, tgt_key_padding_mask=(tgt == 0))
        return self.output_proj(output)
    
    def generate(self, src, tokenizer, max_len=None, temperature=0.6):
        self.eval()
        max_len = max_len or self.max_len
        with torch.no_grad():
            src_emb = self.dropout(self.pos_encoder(self.embedding(src)))
            memory = self.encoder(src_emb, src_key_padding_mask=(src == 0))
            tgt_indices = [tokenizer.word2idx['<SOS>']]
            for _ in range(max_len - 1):
                tgt = torch.tensor([tgt_indices], dtype=torch.long)
                tgt_emb = self.pos_encoder(self.embedding(tgt))
                tgt_mask = nn.Transformer.generate_square_subsequent_mask(len(tgt_indices))
                output = self.decoder(tgt_emb, memory, tgt_mask=tgt_mask)
                logits = self.output_proj(output[0, -1]) / temperature
                probs = torch.softmax(logits, dim=-1)
                top_k = 10
                top_probs, top_indices = torch.topk(probs, top_k)
                next_token = top_indices[torch.multinomial(top_probs, 1)].item()
                if next_token in [tokenizer.word2idx['<EOS>'], tokenizer.word2idx['<PAD>']]:
                    break
                tgt_indices.append(next_token)
        return tokenizer.decode(tgt_indices)


class SimpleTokenizer:
    def __init__(self):
        self.word2idx = {'<PAD>': 0, '<SOS>': 1, '<EOS>': 2, '<UNK>': 3}
        self.idx2word = {0: '<PAD>', 1: '<SOS>', 2: '<EOS>', 3: '<UNK>'}
    
    def load(self, word2idx, idx2word):
        self.word2idx = word2idx
        self.idx2word = idx2word
    
    def _tokenize(self, text):
        text = text.replace('\n', ' <NL> ')
        tokens = re.findall(r'[a-zA-Z0-9_\-\./]+|[\d]+\.[\d]+\.[\d]+\.[\d]+|:[0-9]+|<[A-Z]+>|[<>|&;]', text)
        return [t.lower() for t in tokens if t.strip()]
    
    def encode(self, text, max_len=120):
        tokens = self._tokenize(text)
        indices = [self.word2idx['<SOS>']]
        for token in tokens[:max_len - 2]:
            indices.append(self.word2idx.get(token, self.word2idx['<UNK>']))
        indices.append(self.word2idx['<EOS>'])
        if len(indices) < max_len:
            indices += [self.word2idx['<PAD>']] * (max_len - len(indices))
        return torch.tensor(indices[:max_len], dtype=torch.long)
    
    def decode(self, indices, skip_special=True):
        words = []
        for idx in indices:
            i = int(idx)
            if skip_special and i in [0, 1, 2, 3]:
                if i == 2:
                    break
                continue
            word = self.idx2word.get(i, '<UNK>')
            words.append('\n' if word == '<NL>' else word)
        return ' '.join(words)


# ============================================================
# ЗАГРУЗЧИК МОДЕЛИ (ML + Seq2Seq)
# ============================================================

class DefenseModelLoader:
    """Загрузчик модели защиты: ML классификатор + Seq2Seq генератор"""
    
    def __init__(self, model_path='./models/defense_classifier_v3.pkl', seq2seq_path='./models/seq2seq/defense_transformer_v2.pt'):
        self.model_path = Path(model_path)
        self.seq2seq_path = Path(seq2seq_path)
        self.attack_types = [
            'SQL Injection', 'Brute Force', 'DDoS', 'Port Scan', 'C2 Beacon',
            'DNS Tunnel', 'XSS', 'Lateral Movement', 'Data Exfiltration',
            'Botnet', 'Ransomware', 'Phishing', 'Zero-Day'
        ]
        self.loaded = False
        self._ml_loaded = False
        self._seq2seq_loaded = False
        
        # ML компоненты
        self.vectorizer = None
        self.classifier = None
        self.label_encoder = None
        
        # Seq2Seq компоненты
        self.seq2seq_model = None
        self.src_tokenizer = None
        self.tgt_tokenizer = None
        
        self._keywords = {
            'SQL Injection': ['sql', 'injection', 'sqli', 'union', 'select', 'mysql', 'postgresql'],
            'Brute Force': ['brute', 'force', 'ssh', 'ftp', 'login', 'password', 'hydra'],
            'DDoS': ['ddos', 'syn', 'flood', 'udp', 'icmp', 'amplification', 'slowloris'],
            'Port Scan': ['port', 'scan', 'nmap', 'scanning', 'probe', 'masscan'],
            'C2 Beacon': ['c2', 'beacon', 'command', 'cobalt', 'meterpreter', 'empire'],
            'DNS Tunnel': ['dns', 'tunnel', 'exfil', 'iodine', 'dnscat'],
            'XSS': ['xss', 'script', 'javascript', 'onerror', 'alert', 'cross-site'],
            'Lateral Movement': ['lateral', 'movement', 'smb', 'rdp', 'psexec', 'wmi'],
            'Data Exfiltration': ['exfil', 'data', 'upload', 'transfer', 'leak', 'dump'],
            'Botnet': ['botnet', 'bot', 'zombie', 'mirai', 'gafgyt', 'mozi'],
            'Ransomware': ['ransom', 'encrypt', 'locker', 'wannacry', 'ryuk', 'lockbit'],
            'Phishing': ['phish', 'fake', 'credential', 'spoof', 'social'],
            'Zero-Day': ['zero', 'unknown', 'new', 'suspicious', 'novel', 'zero-day'],
        }
        
        self._load()
    
    def _load(self):
        # Загрузка ML классификатора
        try:
            if self.model_path.exists():
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                self.attack_types = data.get('attack_types', self.attack_types)
                self.vectorizer = data.get('vectorizer')
                self.classifier = data.get('classifier')
                self.label_encoder = data.get('label_encoder')
                if self.vectorizer and self.classifier and self.label_encoder:
                    self._ml_loaded = True
                    logger.info(f"✅ ML модель загружена: {len(self.attack_types)} классов")
        except Exception as e:
            logger.warning(f"ML модель не загружена: {e}")
        
        # Загрузка Seq2Seq генератора
        try:
            import json
            weights_path = Path('./models/seq2seq/model_weights.pt')
            config_path = Path('./models/seq2seq/model_config.json')
            
            if weights_path.exists() and config_path.exists():
                # Загружаем конфиг
                with open(config_path, 'r') as f:
                    cfg = json.load(f)
                
                # Создаём модель
                self.seq2seq_model = Seq2SeqTransformer(
                    vocab_size=cfg['vocab_size'],
                    embed_dim=cfg['embed_dim'],
                    num_heads=cfg['num_heads'],
                    num_layers=cfg['num_layers'],
                    hidden_dim=cfg['hidden_dim'],
                    dropout=cfg['dropout'],
                    max_len=cfg['max_seq_len']
                )
                # Загружаем веса
                self.seq2seq_model.load_state_dict(torch.load(weights_path, map_location='cpu', weights_only=True))
                self.seq2seq_model.eval()
                
                # Загружаем токенизаторы из JSON
                self.src_tokenizer = SimpleTokenizer()
                self.src_tokenizer.load(
                    cfg['src_word2idx'],
                    {int(k): v for k, v in cfg['src_idx2word'].items()}
                )
                self.tgt_tokenizer = SimpleTokenizer()
                self.tgt_tokenizer.load(
                    cfg['tgt_word2idx'],
                    {int(k): v for k, v in cfg['tgt_idx2word'].items()}
                )
                
                self._seq2seq_loaded = True
                params = sum(p.numel() for p in self.seq2seq_model.parameters())
                logger.info(f"✅ Seq2Seq модель загружена: {params:,} параметров")
        except Exception as e:
            logger.warning(f"Seq2Seq модель не загружена: {e}")
        
        self.loaded = True
    
    def predict(self, text: str) -> Tuple[str, float]:
        if self._ml_loaded and self.vectorizer and self.classifier:
            try:
                X = self.vectorizer.transform([text])
                proba = self.classifier.predict_proba(X)[0]
                idx = proba.argmax()
                confidence = float(proba[idx])
                if confidence >= 0.35:
                    predicted = self.label_encoder.inverse_transform([idx])[0]
                    predicted = self._normalize_attack_type(predicted)
                    return predicted, confidence
            except Exception as e:
                logger.debug(f"ML error: {e}")
        return self._keyword_predict(text)
    
    def generate_defense_code(self, attack_text: str, src_ip: str = '0.0.0.0', dst_port: int = 80) -> str:
        """Генерация защитного кода через Seq2Seq нейросеть"""
        if self._seq2seq_loaded and self.seq2seq_model and self.src_tokenizer:
            try:
                # Формируем запрос к модели
                prompt = f"{attack_text} from {src_ip} on port {dst_port}"
                src = self.src_tokenizer.encode(prompt).unsqueeze(0)
                
                # Генерация
                code = self.seq2seq_model.generate(src, self.tgt_tokenizer, temperature=0.5)  # FIXED: use tgt_tokenizer  # FIXED: use tgt_tokenizer
                
                # Постобработка: заменяем <NL> на переносы строк
                code = code.replace(' <NL> ', '\n').replace('<NL>', '\n')
                
                # Корректируем IP если модель ошиблась
                code = re.sub(r'\d+\.\d+\.\d+\.\d+', src_ip, code, count=1)
                
                return f"# SHARD Neural Defense (Seq2Seq Transformer)\n{code}"
            except Exception as e:
                logger.error(f"Seq2Seq generation error: {e}")
        
        # Fallback: шаблонная генерация
        return self._template_defense(attack_text, src_ip, dst_port)
    
    def _template_defense(self, attack_type: str, src_ip: str, dst_port: int) -> str:
        """Шаблонная генерация (fallback)"""
        templates = {
            'SQL Injection': f"iptables -A INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP\n# WAF: ModSecurity SQLi protection",
            'Brute Force': f"iptables -A INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP\niptables -A INPUT -p tcp --dport {dst_port} -m recent --update --seconds 300 --hitcount 3 -j DROP",
            'DDoS': f"iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT\niptables -A INPUT -p tcp --syn -j DROP\necho 1 > /proc/sys/net/ipv4/tcp_syncookies",
            'C2 Beacon': f"iptables -A INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP\niptables -A OUTPUT -d {src_ip} -j DROP",
            'DNS Tunnel': f"iptables -A INPUT -s {src_ip} -p udp --dport 53 -m length --length 512:65535 -j DROP",
            'Zero-Day': f"iptables -A INPUT -s {src_ip} -j DROP\niptables -A OUTPUT -d {src_ip} -j DROP\ntcpdump -i any -w /tmp/shard_zeroday.pcap host {src_ip} &",
        }
        atype = self._normalize_attack_type(attack_type)
        template = templates.get(atype, templates['Zero-Day'])
        return f"# SHARD Template Defense: {atype}\n{template}"
    
    def _keyword_predict(self, text: str) -> Tuple[str, float]:
        text_lower = text.lower()
        scores = {}
        for at, kws in self._keywords.items():
            scores[at] = sum(1 for kw in kws if kw in text_lower)
        best = max(scores, key=scores.get)
        total = sum(scores.values())
        conf = scores[best] / max(1, total) if total > 0 else 0.3
        return best, conf
    
    def _normalize_attack_type(self, attack_type: str) -> str:
        if attack_type in self.attack_types:
            return attack_type
        for at in self.attack_types:
            if at.lower() in attack_type.lower() or attack_type.lower() in at.lower():
                return at
        return attack_type


# ============================================================
# DEFENSE PIPELINE V3
# ============================================================

class DefensePipeline:
    """Defence Pipeline v3 с Seq2Seq генератором"""
    
    def __init__(self):
        self.model = DefenseModelLoader()
        self.rl_agent = None
        if RL_AVAILABLE:
            try:
                self.rl_agent = RLDefenseAgent()
                if self.rl_agent.loaded:
                    logger.info("🤖 RL Defence Agent интегрирован")
            except Exception as e:
                logger.debug(f"RL not loaded: {e}")
        self.stats = {'alerts': 0, 'defense_generated': 0, 'seq2seq_used': 0, 'template_used': 0, 'rl_decisions': 0}
        self._lock = threading.RLock()
    
    def start(self):
        seq2seq_status = "Seq2Seq Transformer (5.3M)" if self.model._seq2seq_loaded else "Templates only"
        ml_status = "XGBoost" if self.model._ml_loaded else "Keyword matching"
        rl_status = "DQN Agent" if (self.rl_agent and self.rl_agent.loaded) else "Rules-based"
        logger.info(f"🛡️ Defense Pipeline v3: ML={ml_status}, Gen={seq2seq_status}, RL={rl_status}")
    
    def process_alert(self, alert: Dict) -> Dict:
        with self._lock:
            self.stats['alerts'] += 1
            
            attack_text = alert.get('explanation', alert.get('attack_type', ''))
            src_ip = alert.get('src_ip', '0.0.0.0')
            dst_port = alert.get('dst_port', 0)
            
            # Классификация
            atype, conf = self.model.predict(attack_text)
            
            # Генерация кода (Seq2Seq если доступен)
            if self.model._seq2seq_loaded:
                code = self.model.generate_defense_code(attack_text, src_ip, dst_port)
                self.stats['seq2seq_used'] += 1
            else:
                code = self.model._template_defense(atype, src_ip, dst_port)
                self.stats['template_used'] += 1
            
            self.stats['defense_generated'] += 1
            # RL Agent принимает решение о действии
            rl_action = None
            if self.rl_agent and self.rl_agent.loaded:
                action_id, action_name, action_desc = self.rl_agent.decide_action({
                    'attack_type': atype,
                    'severity': 'CRITICAL' if conf > 0.8 else 'HIGH' if conf > 0.6 else 'MEDIUM',
                    'score': conf,
                    'confidence': conf,
                    'dst_port': dst_port,
                    'src_ip': src_ip,
                })
                rl_action = {
                    'action_id': action_id,
                    'action_name': action_name,
                    'action_desc': action_desc,
                    'cost': self.rl_agent.get_action_cost(action_id),
                }
                self.stats['rl_decisions'] += 1
                logger.warning(f"🤖 RL: {action_name} (cost={rl_action['cost']})")
            
            logger.warning(f"🛡️ DEFENSE: {atype} ({conf:.0%}) → {src_ip}")
            
            # АВТО-ПРИМЕНЕНИЕ СГЕНЕРИРОВАННОГО КОДА
            if code and 'iptables' in code.lower():
                import subprocess, re
                lines = code.replace('<NL>', '\n').split('\n')
                applied = 0
                for line in lines:
                    line = line.strip()
                    if line.startswith('iptables') and '-j' in line:
                        # Заменяем -A на -C для проверки, потом на -A для применения
                        try:
                            # Проверяем не существует ли уже правило
                            check = line.replace(' -A ', ' -C ')
                            r = subprocess.run(check.split(), capture_output=True, timeout=2)
                            if r.returncode != 0:
                                # Применяем правило
                                r = subprocess.run(line.split(), capture_output=True, timeout=2)
                                if r.returncode == 0:
                                    applied += 1
                        except Exception:
                            pass
                if applied > 0:
                    logger.warning(f"🔧 ПРИМЕНЕНО правил iptables: {applied}")
            
            # Отправляем в Telegram/Slack/Discord
            if _notifier and _notifier.enabled:
                try:
                    _notifier.send_alert({
                        'applied_rules': applied if 'applied' in dir() else 0,
                        'attack_type': atype,
                        'severity': 'CRITICAL' if conf > 0.8 else 'HIGH' if conf > 0.6 else 'MEDIUM',
                        'src_ip': src_ip,
                        'dst_port': dst_port,
                        'confidence': conf,
                        'timestamp': time.time(),
                        'code': code,
                        'rl_action': rl_action,
                    })
                except Exception:
                    pass
            
            # Отправляем в Telegram/Slack/Discord
            if _notifier and _notifier.enabled:
                try:
                    _notifier.send_alert({
                        'applied_rules': applied if 'applied' in dir() else 0,
                        'attack_type': atype,
                        'severity': 'CRITICAL' if conf > 0.8 else 'HIGH' if conf > 0.6 else 'MEDIUM',
                        'src_ip': src_ip,
                        'dst_port': dst_port,
                        'confidence': conf,
                        'timestamp': time.time(),
                        'code': code,
                        'rl_action': rl_action,
                    })
                except Exception:
                    pass
            
            return {
                'attack_type': atype,
                'confidence': conf,
                'code': code,
                'generator': 'seq2seq' if self.model._seq2seq_loaded else 'template',
                'rl_action': rl_action,
            }


# Совместимость
ShardDefensePipeline = DefensePipeline

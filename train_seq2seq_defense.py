#!/usr/bin/env python3
"""
SHARD Seq2Seq Defense Code Generator
Transformer Encoder-Decoder на PyTorch
Генерирует уникальный код защиты (iptables/WAF) под каждую атаку
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import pickle
import logging
from pathlib import Path
from collections import Counter
import re
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-Seq2Seq")

# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

CONFIG = {
    'vocab_size': 500,
    'embed_dim': 128,
    'num_heads': 4,
    'num_layers': 2,
    'hidden_dim': 256,
    'max_seq_len': 100,
    'batch_size': 16,
    'epochs': 30,
    'lr': 0.001,
    'dropout': 0.1,
}

# ============================================================
# ТОКЕНИЗАТОР
# ============================================================

class SimpleTokenizer:
    """Простой токенизатор для кода iptables/WAF"""
    
    def __init__(self, max_vocab=500):
        self.max_vocab = max_vocab
        self.word2idx = {'<PAD>': 0, '<SOS>': 1, '<EOS>': 2, '<UNK>': 3}
        self.idx2word = {0: '<PAD>', 1: '<SOS>', 2: '<EOS>', 3: '<UNK>'}
        self.fitted = False
        
    def fit(self, texts):
        """Обучение словаря на текстах"""
        counter = Counter()
        for text in texts:
            tokens = self._tokenize(text)
            counter.update(tokens)
        
        # Берём top-N слов
        for word, _ in counter.most_common(self.max_vocab - len(self.word2idx)):
            idx = len(self.word2idx)
            self.word2idx[word] = idx
            self.idx2word[idx] = word
        
        self.fitted = True
        logger.info(f"Tokenizer fitted: {len(self.word2idx)} tokens")
    
    def _tokenize(self, text):
        """Токенизация: слова + спецсимволы iptables"""
        # Сохраняем флаги iptables и спецсимволы
        text = text.replace('\n', ' <NL> ')
        # Разбиваем по пробелам и пунктуации
        tokens = re.findall(r'[a-zA-Z0-9_\-\./]+|[<>|&;]', text.lower())
        return tokens
    
    def encode(self, text, max_len=None):
        """Текст → индексы"""
        if not self.fitted:
            raise ValueError("Tokenizer not fitted!")
        
        tokens = self._tokenize(text)
        max_len = max_len or CONFIG['max_seq_len']
        
        # Добавляем <SOS> и <EOS>
        indices = [self.word2idx['<SOS>']]
        for token in tokens[:max_len - 2]:
            indices.append(self.word2idx.get(token, self.word2idx['<UNK>']))
        indices.append(self.word2idx['<EOS>'])
        
        # Паддинг
        if len(indices) < max_len:
            indices += [self.word2idx['<PAD>']] * (max_len - len(indices))
        
        return torch.tensor(indices[:max_len], dtype=torch.long)
    
    def decode(self, indices, skip_special=True):
        """Индексы → текст"""
        words = []
        for idx in indices:
            if skip_special and idx in [0, 1, 2, 3]:
                if idx == 2:  # <EOS>
                    break
                continue
            word = self.idx2word.get(int(idx), '<UNK>')
            if word == '<NL>':
                words.append('\n')
            else:
                words.append(word)
        return ' '.join(words)


# ============================================================
# ГЕНЕРАТОР ДАТАСЕТА
# ============================================================

def create_dataset() -> list:
    """Создание расширенного датасета атака → защитный код"""
    
    defense_rules = {
        'SQL Injection': [
            ('SQL injection from {ip} on port {port}',
             'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
             'iptables -A INPUT -p tcp --dport {port} -m string --string "UNION SELECT" --algo bm -j DROP\n'
             'SecRule REQUEST_URI "@rx union.*select" "id:1001,phase:2,deny,status:403"'),
            ('Blind SQLi from {ip}:{port}',
             'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
             'iptables -A INPUT -p tcp --dport {port} -m string --string "1=1" --algo bm -j DROP\n'
             'iptables -A INPUT -s {ip} -j LOG --log-prefix "SQLi:"'),
        ],
        'Brute Force': [
            ('SSH brute force from {ip}:{port}',
             'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
             'iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP\n'
             'iptables -A INPUT -s {ip} -j LOG --log-prefix "BRUTE:"'),
            ('FTP brute force {ip} on port {port}',
             'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
             'iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP'),
        ],
        'DDoS': [
            ('SYN flood DDoS from {ip} on port {port}',
             'iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT\n'
             'iptables -A INPUT -p tcp --syn -j DROP\n'
             'sysctl -w net.ipv4.tcp_syncookies=1\n'
             'iptables -A INPUT -s {ip} -j DROP'),
            ('UDP flood from {ip} port {port}',
             'iptables -A INPUT -p udp --dport {port} -m limit --limit 100/s -j ACCEPT\n'
             'iptables -A INPUT -p udp --dport {port} -j DROP\n'
             'iptables -A INPUT -s {ip} -j DROP'),
        ],
        'C2 Beacon': [
            ('C2 beacon from {ip} on port {port}',
             'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
             'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP\n'
             'iptables -A FORWARD -s {ip} -j DROP\n'
             'iptables -A INPUT -s {ip} -j LOG --log-prefix "C2:"'),
        ],
        'DNS Tunnel': [
            ('DNS tunnel from {ip}',
             'iptables -A INPUT -s {ip} -p udp --dport 53 -m length --length 512:65535 -j DROP\n'
             'iptables -A INPUT -s {ip} -p udp --dport 53 -m string --hex-string "|0000|" --algo bm -j DROP'),
        ],
        'Data Exfiltration': [
            ('Data exfiltration to {ip}:{port}',
             'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP\n'
             'iptables -A OUTPUT -d {ip} -j DROP\n'
             'iptables -A OUTPUT -d {ip} -j LOG --log-prefix "EXFIL:"'),
        ],
        'Botnet': [
            ('Botnet C2 from {ip}',
             'iptables -A INPUT -s {ip} -j DROP\n'
             'iptables -A OUTPUT -d {ip} -j DROP\n'
             'iptables -A FORWARD -s {ip} -j DROP\n'
             'iptables -A FORWARD -d {ip} -j DROP'),
        ],
        'Ransomware': [
            ('Ransomware activity from {ip}',
             'iptables -A INPUT -s {ip} -j DROP\n'
             'iptables -A OUTPUT -d {ip} -j DROP\n'
             'iptables -A OUTPUT -p tcp --dport 445 -j DROP\n'
             'iptables -A FORWARD -s {ip} -j DROP'),
        ],
        'Zero-Day': [
            ('Unknown attack from {ip}:{port}',
             'iptables -A INPUT -s {ip} -j DROP\n'
             'iptables -A OUTPUT -d {ip} -j DROP\n'
             'tcpdump -i any -w /tmp/shard_zeroday_$(date +%s).pcap host {ip} &\n'
             'iptables -A INPUT -s {ip} -j LOG --log-prefix "ZERODAY:"'),
        ],
    }
    
    ips = [f'10.0.0.{i}' for i in range(1, 20)] + \
          [f'192.168.1.{i}' for i in range(1, 20)] + \
          [f'172.16.0.{i}' for i in range(1, 10)] + \
          ['185.142.53.101', '45.155.205.233', '194.61.23.45']
    
    ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 4444, 5555, 9090]
    
    samples = []
    
    for attack_type, variants in defense_rules.items():
        for attack_template, defense_template in variants:
            for ip in ips:
                for port in ports[:4]:  # 4 порта на IP
                    attack = attack_template.format(ip=ip, port=port)
                    defense = defense_template.format(ip=ip, port=port)
                    samples.append({'attack': attack, 'defense': defense})
    
    logger.info(f"Dataset created: {len(samples)} samples")
    return samples


# ============================================================
# TRANSFORMER МОДЕЛЬ
# ============================================================

class PositionalEncoding(nn.Module):
    """Позиционное кодирование для Transformer"""
    
    def __init__(self, d_model, max_len=100):
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
    """Transformer Encoder-Decoder для генерации защитного кода"""
    
    def __init__(self, vocab_size, embed_dim=128, num_heads=4, num_layers=2, hidden_dim=256, dropout=0.1, max_len=100):
        super().__init__()
        
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_encoder = PositionalEncoding(embed_dim, max_len)
        
        # Encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim,
            dropout=dropout,
            activation='relu',
            batch_first=True
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Decoder
        decoder_layer = nn.TransformerDecoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim,
            dropout=dropout,
            activation='relu',
            batch_first=True
        )
        self.decoder = nn.TransformerDecoder(decoder_layer, num_layers=num_layers)
        
        # Output projection
        self.output_proj = nn.Linear(embed_dim, vocab_size)
        
        self.dropout = nn.Dropout(dropout)
        self.max_len = max_len
        self.vocab_size = vocab_size
        
    def forward(self, src, tgt, src_mask=None, tgt_mask=None):
        # Энкодер
        src_emb = self.embedding(src)
        src_emb = self.pos_encoder(src_emb)
        src_emb = self.dropout(src_emb)
        memory = self.encoder(src_emb, src_key_padding_mask=(src == 0))
        
        # Декодер
        tgt_emb = self.embedding(tgt)
        tgt_emb = self.pos_encoder(tgt_emb)
        tgt_emb = self.dropout(tgt_emb)
        
        # Причинная маска для декодера
        if tgt_mask is None:
            tgt_mask = nn.Transformer.generate_square_subsequent_mask(tgt.size(1)).to(tgt.device)
        
        output = self.decoder(tgt_emb, memory, tgt_mask=tgt_mask, tgt_key_padding_mask=(tgt == 0))
        return self.output_proj(output)
    
    def generate(self, src, tokenizer, max_len=None, temperature=0.7):
        """Генерация кода защиты"""
        self.eval()
        max_len = max_len or self.max_len
        
        with torch.no_grad():
            # Энкодер
            src_emb = self.embedding(src)
            src_emb = self.pos_encoder(src_emb)
            memory = self.encoder(src_emb, src_key_padding_mask=(src == 0))
            
            # Начинаем с <SOS>
            tgt_indices = [tokenizer.word2idx['<SOS>']]
            
            for _ in range(max_len - 1):
                tgt = torch.tensor([tgt_indices], dtype=torch.long)
                tgt_emb = self.embedding(tgt)
                tgt_emb = self.pos_encoder(tgt_emb)
                
                tgt_mask = nn.Transformer.generate_square_subsequent_mask(len(tgt_indices))
                
                output = self.decoder(tgt_emb, memory, tgt_mask=tgt_mask)
                logits = self.output_proj(output[0, -1]) / temperature
                
                # Семплирование
                probs = torch.softmax(logits, dim=-1)
                next_token = torch.multinomial(probs, 1).item()
                
                # <EOS> или <PAD> — стоп
                if next_token in [tokenizer.word2idx['<EOS>'], tokenizer.word2idx['<PAD>']]:
                    break
                
                tgt_indices.append(next_token)
            
            return tokenizer.decode(tgt_indices)


# ============================================================
# ОБУЧЕНИЕ
# ============================================================

class DefenseDataset(Dataset):
    def __init__(self, samples, src_tokenizer, tgt_tokenizer, max_len=100):
        self.samples = samples
        self.src_tokenizer = src_tokenizer
        self.tgt_tokenizer = tgt_tokenizer
        self.max_len = max_len
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx):
        sample = self.samples[idx]
        src = self.src_tokenizer.encode(sample['attack'], self.max_len)
        tgt = self.tgt_tokenizer.encode(sample['defense'], self.max_len)
        return src, tgt


def train():
    logger.info("=" * 60)
    logger.info("🧠 SHARD Seq2Seq Defense Code Generator (PyTorch Transformer)")
    logger.info("=" * 60)
    
    # Датасет
    logger.info("\n📊 Creating dataset...")
    samples = create_dataset()
    
    # Токенизаторы
    logger.info("🔤 Building tokenizers...")
    src_tokenizer = SimpleTokenizer(max_vocab=CONFIG['vocab_size'])
    tgt_tokenizer = SimpleTokenizer(max_vocab=CONFIG['vocab_size'])
    
    src_tokenizer.fit([s['attack'] for s in samples])
    tgt_tokenizer.fit([s['defense'] for s in samples])
    
    # DataLoader
    dataset = DefenseDataset(samples, src_tokenizer, tgt_tokenizer, CONFIG['max_seq_len'])
    dataloader = DataLoader(dataset, batch_size=CONFIG['batch_size'], shuffle=True)
    
    logger.info(f"   Samples: {len(samples)}")
    logger.info(f"   Source vocab: {len(src_tokenizer.word2idx)}")
    logger.info(f"   Target vocab: {len(tgt_tokenizer.word2idx)}")
    
    # Модель
    logger.info(f"\n🧠 Creating Transformer model...")
    vocab_size = max(len(src_tokenizer.word2idx), len(tgt_tokenizer.word2idx)) + 1
    model = Seq2SeqTransformer(
        vocab_size=vocab_size,
        embed_dim=CONFIG['embed_dim'],
        num_heads=CONFIG['num_heads'],
        num_layers=CONFIG['num_layers'],
        hidden_dim=CONFIG['hidden_dim'],
        dropout=CONFIG['dropout'],
        max_len=CONFIG['max_seq_len']
    )
    
    total_params = sum(p.numel() for p in model.parameters())
    logger.info(f"   Parameters: {total_params:,}")
    logger.info(f"   Device: {'GPU' if torch.cuda.is_available() else 'CPU'}")
    
    # Оптимизатор и лосс
    optimizer = optim.Adam(model.parameters(), lr=CONFIG['lr'])
    criterion = nn.CrossEntropyLoss(ignore_index=0)  # Игнорируем PAD
    
    # Обучение
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        
        for batch_idx, (src, tgt) in enumerate(dataloader):
            # Teacher forcing: decoder input = tgt[:-1], output = tgt[1:]
            tgt_input = tgt[:, :-1]
            tgt_output = tgt[:, 1:]
            
            # Forward
            output = model(src, tgt_input)
            
            # Loss
            output_flat = output.reshape(-1, vocab_size)
            tgt_flat = tgt_output.reshape(-1)
            loss = criterion(output_flat, tgt_flat)
            
            # Backward
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item()
            
            if batch_idx % 50 == 0:
                logger.info(f"   Epoch {epoch+1}/{CONFIG['epochs']}, Batch {batch_idx}: loss={loss.item():.4f}")
        
        avg_loss = total_loss / len(dataloader)
        logger.info(f"✅ Epoch {epoch+1}/{CONFIG['epochs']}: avg_loss={avg_loss:.4f}")
    
    # Сохранение
    logger.info(f"\n💾 Saving model...")
    Path('./models/seq2seq').mkdir(parents=True, exist_ok=True)
    
    torch.save({
        'model_state_dict': model.state_dict(),
        'src_tokenizer': src_tokenizer,
        'tgt_tokenizer': tgt_tokenizer,
        'config': CONFIG,
        'vocab_size': vocab_size,
    }, './models/seq2seq/defense_transformer.pt')
    
    logger.info("✅ Model saved: models/seq2seq/defense_transformer.pt")
    
    # Тест генерации
    logger.info(f"\n🧪 Testing code generation...")
    model.eval()
    
    test_attacks = [
        "SQL injection from 10.0.0.5 on port 3306",
        "SSH brute force from 192.168.1.100:22",
        "SYN flood DDoS from 185.142.53.101 on port 443",
        "C2 beacon from 45.155.205.233 on port 4444",
        "DNS tunnel from 172.16.0.7",
    ]
    
    for attack in test_attacks:
        src = src_tokenizer.encode(attack).unsqueeze(0)
        generated = model.generate(src, tgt_tokenizer, temperature=0.5)
        logger.info(f"\n   Attack: {attack}")
        logger.info(f"   Defense:\n{generated[:150]}...")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ TRAINING COMPLETE!")
    logger.info(f"📁 Model: models/seq2seq/defense_transformer.pt")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    train()

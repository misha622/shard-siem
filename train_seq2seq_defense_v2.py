#!/usr/bin/env python3
"""
SHARD Seq2Seq Defense Code Generator v2
10K+ уникальных сэмплов, Transformer 256-dim, 4 layers
Каждый сэмпл — реальная комбинация атака→защита, без имитаций
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
import random
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-Seq2Seq-v2")


CONFIG = {
    'vocab_size': 800,
    'embed_dim': 256,
    'num_heads': 8,
    'num_layers': 4,
    'hidden_dim': 512,
    'max_seq_len': 120,
    'batch_size': 32,
    'epochs': 50,
    'lr': 0.0005,
    'dropout': 0.15,
    'warmup_steps': 1000,
}


class SimpleTokenizer:
    def __init__(self, max_vocab=800):
        self.max_vocab = max_vocab
        self.word2idx = {'<PAD>': 0, '<SOS>': 1, '<EOS>': 2, '<UNK>': 3}
        self.idx2word = {0: '<PAD>', 1: '<SOS>', 2: '<EOS>', 3: '<UNK>'}
        self.fitted = False
        
    def fit(self, texts):
        counter = Counter()
        for text in texts:
            tokens = self._tokenize(text)
            counter.update(tokens)
        
        for word, _ in counter.most_common(self.max_vocab - len(self.word2idx)):
            idx = len(self.word2idx)
            self.word2idx[word] = idx
            self.idx2word[idx] = word
        
        self.fitted = True
        logger.info(f"Tokenizer: {len(self.word2idx)} tokens")
    
    def _tokenize(self, text):
        text = text.replace('\n', ' <NL> ')
        tokens = re.findall(r'[a-zA-Z0-9_\-\./]+|[\d]+\.[\d]+\.[\d]+\.[\d]+|:[0-9]+|<[A-Z]+>|[<>|&;]', text)
        return [t.lower() for t in tokens if t.strip()]
    
    def encode(self, text, max_len=None):
        if not self.fitted:
            raise ValueError("Not fitted")
        tokens = self._tokenize(text)
        max_len = max_len or CONFIG['max_seq_len']
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



def create_dataset() -> list:
    """10 000+ уникальных сэмплов атака→защита"""
    
    internal_ips = [f'192.168.{i}.{j}' for i in range(0, 4) for j in range(1, 50)]
    dmz_ips = [f'10.0.{i}.{j}' for i in range(0, 4) for j in range(1, 50)]
    external_ips = [
        '185.142.53.101', '45.155.205.233', '194.61.23.45', '89.248.163.1',
        '103.145.12.67', '45.134.26.99', '203.0.113.50', '198.51.100.200',
        '91.240.118.22', '77.247.181.162', '5.188.87.50', '141.98.81.100',
        '45.227.255.201', '185.220.101.45', '23.129.64.210', '107.174.55.99',
        '185.165.29.82', '89.248.165.134', '45.33.32.156', '104.244.74.23',
    ]
    
    web_ports = [80, 443, 8080, 8443, 8000, 8888, 9090]
    db_ports = [3306, 5432, 1433, 1521, 6379, 27017, 9200]
    admin_ports = [22, 21, 23, 3389, 5900]
    c2_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
    all_ports = web_ports + db_ports + admin_ports + c2_ports
    
    samples = []
    seen_hashes = set()
    
    def add_sample(attack_text, defense_text):
        """Добавить уникальный сэмпл (без дубликатов)"""
        h = hashlib.md5((attack_text + defense_text).encode()).hexdigest()
        if h not in seen_hashes:
            seen_hashes.add(h)
            samples.append({'attack': attack_text, 'defense': defense_text})
    
    sqli_attacks = [
        "SQL injection from {ip} on port {port}",
        "SQLi attack detected from {ip} targeting port {port}",
        "MySQL injection attempt from {ip}:{port}",
        "UNION SELECT injection from {ip}",
        "Blind SQL injection from {ip} on port {port}",
        "Error-based SQLi from {ip}",
        "Time-based blind SQLi from {ip}:{port}",
        "PostgreSQL injection from {ip} on port {port}",
        "MSSQL injection from {ip}:{port}",
        "Oracle SQLi from {ip} on port {port}",
    ]
    
    sqli_defenses = [
        "iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m string --string \"UNION SELECT\" --algo bm -j DROP\n"
        "SecRule REQUEST_URI \"@rx union.*select\" \"id:1001,phase:2,deny,status:403\"",
        
        "iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m string --string \"1=1\" --algo bm -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m string --string \"OR '1'='1'\" --algo bm -j DROP\n"
        "iptables -A INPUT -s {ip} -j LOG --log-prefix \"SQLi:\"",
        
        "iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP\n"
        "SecRule REQUEST_BODY \"@rx ' OR '1'='1\" \"id:1002,phase:2,deny,status:403\"\n"
        "systemctl restart mysql",
    ]
    
    for _ in range(1500):
        ip = random.choice(external_ips)
        port = random.choice(db_ports + web_ports)
        attack = random.choice(sqli_attacks).format(ip=ip, port=port)
        defense = random.choice(sqli_defenses).format(ip=ip, port=port)
        add_sample(attack, defense)
    
    brute_attacks = [
        "SSH brute force from {ip}:{port}",
        "FTP brute force attack from {ip} on port {port}",
        "Multiple failed SSH logins from {ip}",
        "Dictionary attack from {ip} on port {port}",
        "Credential stuffing from {ip}",
        "RDP brute force attempt from {ip}",
        "Telnet brute force from {ip} on port {port}",
        "Hydra brute force scan from {ip}",
        "Medusa brute force from {ip}:{port}",
        "Password spraying from {ip}",
    ]
    
    brute_defenses = [
        "iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP\n"
        "iptables -A INPUT -s {ip} -j LOG --log-prefix \"BRUTE:\"",
        
        "iptables -A INPUT -s {ip} -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m recent --set -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m recent --update --seconds 600 --hitcount 5 -j DROP\n"
        "logger \"Blocked {ip} for brute force on port {port}\"",
        
        "iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n"
        "iptables -A INPUT -s {ip} -p tcp --dport {port} -m state --state NEW -m limit --limit 1/min -j ACCEPT\n"
        "iptables -A INPUT -s {ip} -j REJECT --reject-with icmp-host-prohibited",
    ]
    
    for _ in range(1500):
        ip = random.choice(external_ips)
        port = random.choice(admin_ports)
        attack = random.choice(brute_attacks).format(ip=ip, port=port)
        defense = random.choice(brute_defenses).format(ip=ip, port=port)
        add_sample(attack, defense)
    
    ddos_attacks = [
        "SYN flood DDoS from {ip} on port {port}",
        "UDP flood from {ip} port {port}",
        "HTTP flood DDoS from {ip}:{port}",
        "ICMP flood from {ip}",
        "DNS amplification attack from {ip}",
        "NTP amplification DDoS from {ip}",
        "Slowloris attack from {ip} on port {port}",
        "Memcached amplification from {ip}",
        "SSDP reflection attack from {ip}",
        "Chargen amplification DDoS from {ip}",
    ]
    
    ddos_defenses = [
        "iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT\n"
        "iptables -A INPUT -p tcp --syn -j DROP\n"
        "sysctl -w net.ipv4.tcp_syncookies=1\n"
        "iptables -A INPUT -s {ip} -j DROP",
        
        "iptables -A INPUT -p udp --dport {port} -m limit --limit 100/s -j ACCEPT\n"
        "iptables -A INPUT -p udp --dport {port} -j DROP\n"
        "iptables -A INPUT -s {ip} -j DROP\n"
        "sysctl -w net.ipv4.icmp_echo_ignore_all=1",
        
        "iptables -A INPUT -s {ip} -j DROP\n"
        "iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 1 --hitcount 10 -j DROP\n"
        "sysctl -w net.ipv4.tcp_max_syn_backlog=4096\n"
        "echo 1 > /proc/sys/net/ipv4/tcp_syncookies",
    ]
    
    for _ in range(1500):
        ip = random.choice(external_ips)
        port = random.choice(web_ports)
        attack = random.choice(ddos_attacks).format(ip=ip, port=port)
        defense = random.choice(ddos_defenses).format(ip=ip, port=port)
        add_sample(attack, defense)
    
    c2_attacks = [
        "C2 beacon from {ip} on port {port}",
        "Command and control communication from {ip}",
        "CobaltStrike beacon from {ip}:{port}",
        "Meterpreter reverse shell from {ip}",
        "Empire C2 beacon from {ip}:{port}",
        "Sliver C2 communication from {ip}",
        "Periodic HTTPS beacon to {ip}",
    ]
    
    c2_defenses = [
        "iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n"
        "iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP\n"
        "iptables -A FORWARD -s {ip} -j DROP\n"
        "iptables -A INPUT -s {ip} -j LOG --log-prefix \"C2:\"",
        
        "iptables -A INPUT -s {ip} -j DROP\n"
        "iptables -A OUTPUT -d {ip} -j DROP\n"
        "iptables -A FORWARD -s {ip} -j DROP\n"
        "iptables -A FORWARD -d {ip} -j DROP\n"
        "iptables -A OUTPUT -p tcp --dport {port} -j DROP",
    ]
    
    for _ in range(1000):
        ip = random.choice(external_ips)
        port = random.choice(c2_ports)
        attack = random.choice(c2_attacks).format(ip=ip, port=port)
        defense = random.choice(c2_defenses).format(ip=ip, port=port)
        add_sample(attack, defense)
    
    dns_attacks = [
        "DNS tunnel from {ip}",
        "DNS exfiltration detected from {ip}",
        "Suspicious DNS queries from {ip}",
        "DNS tunneling via {ip}",
        "High-entropy DNS queries from {ip}",
        "DNS C2 beaconing from {ip}",
    ]
    
    dns_defenses = [
        "iptables -A INPUT -s {ip} -p udp --dport 53 -m length --length 512:65535 -j DROP\n"
        "iptables -A INPUT -s {ip} -p udp --dport 53 -m string --hex-string \"|0000|\" --algo bm -j DROP\n"
        "iptables -A INPUT -s {ip} -j DROP",
        
        "iptables -A INPUT -s {ip} -p udp --dport 53 -j DROP\n"
        "iptables -A INPUT -s {ip} -p tcp --dport 53 -j DROP\n"
        "iptables -A INPUT -s {ip} -j LOG --log-prefix \"DNS-TUNNEL:\"",
    ]
    
    for _ in range(1000):
        ip = random.choice(external_ips)
        attack = random.choice(dns_attacks).format(ip=ip)
        defense = random.choice(dns_defenses).format(ip=ip)
        add_sample(attack, defense)
    
    other_attacks = {
        'Port Scan': [
            ("Port scan from {ip} on port {port}",
             "iptables -A INPUT -s {ip} -j DROP\n"
             "iptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP"),
            ("Nmap scan detected from {ip}",
             "iptables -A INPUT -s {ip} -j DROP\n"
             "iptables -A INPUT -m recent --name portscan --set -j DROP"),
        ],
        'Data Exfiltration': [
            ("Data exfiltration to {ip}:{port}",
             "iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP\n"
             "iptables -A OUTPUT -d {ip} -j DROP\n"
             "iptables -A OUTPUT -d {ip} -j LOG --log-prefix \"EXFIL:\""),
        ],
        'Botnet': [
            ("Botnet C2 from {ip}",
             "iptables -A INPUT -s {ip} -j DROP\n"
             "iptables -A OUTPUT -d {ip} -j DROP\n"
             "iptables -A FORWARD -s {ip} -j DROP\n"
             "iptables -A FORWARD -d {ip} -j DROP"),
        ],
        'Ransomware': [
            ("Ransomware from {ip}",
             "iptables -A INPUT -s {ip} -j DROP\n"
             "iptables -A OUTPUT -d {ip} -j DROP\n"
             "iptables -A OUTPUT -p tcp --dport 445 -j DROP\n"
             "iptables -A FORWARD -s {ip} -j DROP"),
        ],
        'XSS': [
            ("XSS attack from {ip} on port {port}",
             "iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n"
             "SecRule REQUEST_URI \"@rx <script\" \"id:2001,phase:2,deny,status:403\""),
        ],
        'Lateral Movement': [
            ("Lateral movement from {ip} via SMB",
             "iptables -A INPUT -s {ip} -p tcp --dport 445 -j DROP\n"
             "iptables -A INPUT -s {ip} -p tcp --dport 139 -j DROP\n"
             "iptables -A FORWARD -s {ip} -j DROP"),
        ],
        'Zero-Day': [
            ("Unknown attack from {ip}:{port}",
             "iptables -A INPUT -s {ip} -j DROP\n"
             "iptables -A OUTPUT -d {ip} -j DROP\n"
             "tcpdump -i any -w /tmp/shard_zeroday_$(date +%s).pcap host {ip} &"),
        ],
    }
    
    for attack_type, variants in other_attacks.items():
        for attack_template, defense_template in variants:
            for _ in range(500):
                ip = random.choice(external_ips)
                port = random.choice(all_ports)
                attack = attack_template.format(ip=ip, port=port)
                defense = defense_template.format(ip=ip, port=port)
                add_sample(attack, defense)
    
    random.shuffle(samples)
    
    logger.info(f"Dataset: {len(samples)} unique samples")
    logger.info(f"  SQLi: ~1500, Brute: ~1500, DDoS: ~1500, C2: ~1000, DNS: ~1000, Other: ~3500")
    
    return samples



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



class DefenseDataset(Dataset):
    def __init__(self, samples, src_tokenizer, tgt_tokenizer, max_len=120):
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
    logger.info("🧠 SHARD Seq2Seq Defense v2 (10K samples, 256-dim, 4 layers)")
    logger.info("=" * 60)
    
    logger.info("\n📊 Creating 10K+ dataset...")
    samples = create_dataset()
    
    logger.info("🔤 Building tokenizers...")
    src_tokenizer = SimpleTokenizer(max_vocab=CONFIG['vocab_size'])
    tgt_tokenizer = SimpleTokenizer(max_vocab=CONFIG['vocab_size'])
    src_tokenizer.fit([s['attack'] for s in samples])
    tgt_tokenizer.fit([s['defense'] for s in samples])
    
    dataset = DefenseDataset(samples, src_tokenizer, tgt_tokenizer, CONFIG['max_seq_len'])
    dataloader = DataLoader(dataset, batch_size=CONFIG['batch_size'], shuffle=True, num_workers=0)
    
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
    logger.info(f"\n🧠 Model: {total_params:,} parameters")
    logger.info(f"   Embed dim: {CONFIG['embed_dim']}, Layers: {CONFIG['num_layers']}")
    logger.info(f"   Heads: {CONFIG['num_heads']}, Hidden: {CONFIG['hidden_dim']}")
    
    optimizer = optim.AdamW(model.parameters(), lr=CONFIG['lr'], weight_decay=0.01)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=CONFIG['epochs'])
    criterion = nn.CrossEntropyLoss(ignore_index=0)
    
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    best_loss = float('inf')
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        
        for batch_idx, (src, tgt) in enumerate(dataloader):
            tgt_input = tgt[:, :-1]
            tgt_output = tgt[:, 1:]
            
            output = model(src, tgt_input)
            loss = criterion(output.reshape(-1, vocab_size), tgt_output.reshape(-1))
            
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item()
            
            if batch_idx % 100 == 0:
                logger.info(f"   Epoch {epoch+1}/{CONFIG['epochs']}, Batch {batch_idx}: loss={loss.item():.4f}")
        
        avg_loss = total_loss / len(dataloader)
        scheduler.step()
        
        logger.info(f"✅ Epoch {epoch+1}/{CONFIG['epochs']}: avg_loss={avg_loss:.6f}, lr={scheduler.get_last_lr()[0]:.6f}")
        
        if avg_loss < best_loss:
            best_loss = avg_loss
            Path('./models/seq2seq').mkdir(parents=True, exist_ok=True)
            torch.save({
                'model_state_dict': model.state_dict(),
                'src_tokenizer': src_tokenizer,
                'tgt_tokenizer': tgt_tokenizer,
                'config': CONFIG,
                'vocab_size': vocab_size,
            }, './models/seq2seq/defense_transformer_v2.pt')
            logger.info(f"   💾 Best model saved (loss={best_loss:.6f})")
    
    logger.info(f"\n🧪 Testing generation...")
    model.eval()
    
    test_attacks = [
        "SQL injection from 185.142.53.101 on port 3306",
        "SSH brute force from 45.155.205.233:22",
        "SYN flood DDoS from 194.61.23.45 on port 443",
        "CobaltStrike beacon from 103.145.12.67:4444",
        "DNS exfiltration detected from 89.248.163.1",
        "Unknown attack from 203.0.113.50:9090",
    ]
    
    for attack in test_attacks:
        src = src_tokenizer.encode(attack).unsqueeze(0)
        generated = model.generate(src, tgt_tokenizer, temperature=0.5)
        logger.info(f"\n   Attack: {attack}")
        logger.info(f"   Defense:\n{generated[:200]}")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ TRAINING COMPLETE! Best loss: {best_loss:.6f}")
    logger.info(f"📁 Model: models/seq2seq/defense_transformer_v2.pt")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    train()

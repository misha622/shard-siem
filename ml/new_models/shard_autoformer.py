#!/usr/bin/env python3
"""
SHARD Autoformer (#43) — Decomposition Transformer для временных рядов атак.
Ключевая инновация: Auto-Correlation механизм вместо self-attention.
Прогрессивная декомпозиция тренда и сезонности на каждом слое.
"""

import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F

logger = logging.getLogger("SHARD-Autoformer")

class SeriesDecomp(nn.Module):
    """Прогрессивная декомпозиция: тренд + сезонность"""
    def __init__(self, kernel_size=25):
        super().__init__()
        self.avg = nn.AvgPool1d(kernel_size=kernel_size, stride=1, padding=kernel_size//2)
    
    def forward(self, x):
        trend = self.avg(x.transpose(1,2)).transpose(1,2)
        seasonal = x - trend
        return seasonal, trend

class AutoCorrelationLayer(nn.Module):
    """Auto-Correlation — замена self-attention через FFT"""
    def __init__(self, d_model, n_heads=8, factor=1):
        super().__init__()
        self.d_model = d_model
        self.n_heads = n_heads
        self.factor = factor
        self.W_Q = nn.Linear(d_model, d_model)
        self.W_K = nn.Linear(d_model, d_model)
        self.W_V = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)
    
    def time_delay_agg(self, queries, keys, values):
        B, L, D = queries.shape
        # FFT-based auto-correlation
        q_fft = torch.fft.rfft(queries.float(), dim=1)
        k_fft = torch.fft.rfft(keys.float(), dim=1)
        res = q_fft * torch.conj(k_fft)
        corr = torch.fft.irfft(res, dim=1)
        
        # Top-k задержек
        top_k = max(1, int(self.factor * np.log(L)))
        weights = torch.topk(corr.mean(-1).mean(-1), top_k, dim=-1).values
        weights = F.softmax(weights, dim=-1).unsqueeze(-1).unsqueeze(-1)
        
        # Агрегация с задержками
        agg = torch.zeros_like(values)
        for i in range(top_k):
            tau = i + 1
            rolled = torch.roll(values, shifts=tau, dims=1)
            agg += weights[:, i:i+1] * rolled
        return agg
    
    def forward(self, x):
        B, L, D = x.shape
        Q = self.W_Q(x).view(B, L, self.n_heads, D//self.n_heads).transpose(1,2)
        K = self.W_K(x).view(B, L, self.n_heads, D//self.n_heads).transpose(1,2)
        V = self.W_V(x).view(B, L, self.n_heads, D//self.n_heads).transpose(1,2)
        
        Q, K, V = Q.reshape(-1, L, D//self.n_heads), K.reshape(-1, L, D//self.n_heads), V.reshape(-1, L, D//self.n_heads)
        attn_out = self.time_delay_agg(Q, K, V)
        attn_out = attn_out.reshape(B, self.n_heads, L, D//self.n_heads).transpose(1,2).reshape(B, L, D)
        return self.out_proj(attn_out)

class AutoformerBlock(nn.Module):
    def __init__(self, d_model, n_heads=8, moving_avg=25):
        super().__init__()
        self.decomp1 = SeriesDecomp(moving_avg)
        self.decomp2 = SeriesDecomp(moving_avg)
        self.auto_corr = AutoCorrelationLayer(d_model, n_heads)
        self.feed_forward = nn.Sequential(nn.Linear(d_model, d_model*4), nn.GELU(), nn.Linear(d_model*4, d_model))
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(0.1)
    
    def forward(self, x):
        seasonal, trend = self.decomp1(x)
        seasonal = seasonal + self.dropout(self.auto_corr(self.norm1(seasonal)))
        seasonal, trend2 = self.decomp2(seasonal)
        seasonal = seasonal + self.dropout(self.feed_forward(self.norm2(seasonal)))
        return seasonal + trend + trend2

class AutoformerDetector(nn.Module):
    def __init__(self, input_dim=76, d_model=128, num_layers=2, num_classes=2):
        super().__init__()
        self.embed = nn.Linear(input_dim, d_model)
        self.blocks = nn.ModuleList([AutoformerBlock(d_model) for _ in range(num_layers)])
        self.head = nn.Sequential(nn.LayerNorm(d_model), nn.Linear(d_model, num_classes))
    
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        x = self.embed(x)
        for block in self.blocks: x = block(x)
        return self.head(x.mean(dim=1))

class AutoformerWrapper:
    def __init__(self, input_dim=76):
        self.model = AutoformerDetector(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.AdamW(self.model.parameters(), lr=0.0001)
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            loss = F.cross_entropy(self.model(X_t), y_t)
            loss.backward()
            opt.step()
        self.is_trained = True
        return {'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad(): probs = F.softmax(self.model(X_t), dim=-1)[:,1].cpu().numpy()
        return (probs>0.5).astype(int), probs

logger.info("✅ Autoformer ready (#43)")

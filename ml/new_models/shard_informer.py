#!/usr/bin/env python3
"""
SHARD Informer (#44) — ProbSparse self-attention для длинных последовательностей.
Ключевая идея: только top-u запросов важны, остальные — uniform.
Self-attention distilling: уменьшение размера последовательности вдвое на каждом слое.
"""

import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F

logger = logging.getLogger("SHARD-Informer")

class ProbSparseAttention(nn.Module):
    """ProbSparse Attention — O(L log L) вместо O(L²)"""
    def __init__(self, d_model, n_heads=8, factor=5):
        super().__init__()
        self.d_model = d_model
        self.n_heads = n_heads
        self.factor = factor
        self.W_Q = nn.Linear(d_model, d_model)
        self.W_K = nn.Linear(d_model, d_model)
        self.W_V = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)
    
    def _prob_QK(self, Q, K, sample_k, top_u):
        """Измеряет разреженность запросов"""
        B, H, L, D = Q.shape
        K_sample = K[:, :, torch.randint(0, L, (sample_k,)), :]
        Q_K_sample = torch.matmul(Q, K_sample.transpose(-2, -1))
        M = Q_K_sample.max(-1)[0] - Q_K_sample.mean(-1)
        return M.topk(top_u, dim=-1).indices
    
    def forward(self, x):
        B, L, D = x.shape
        Q = self.W_Q(x).view(B, L, self.n_heads, D//self.n_heads).transpose(1,2)
        K = self.W_K(x).view(B, L, self.n_heads, D//self.n_heads).transpose(1,2)
        V = self.W_V(x).view(B, L, self.n_heads, D//self.n_heads).transpose(1,2)
        
        u = max(1, int(self.factor * np.log(L)))
        top_idx = self._prob_QK(Q, K, sample_k=max(1, int(np.log(L))), top_u=u)
        
        # Sparse attention только для top-u запросов
        Q_reduced = Q.gather(2, top_idx.unsqueeze(-1).expand(-1, -1, -1, D//self.n_heads))
        attn = F.softmax(torch.matmul(Q_reduced, K.transpose(-2, -1)) / (D**0.5), dim=-1)
        out = torch.matmul(attn, V)
        out = out.transpose(1,2).reshape(B, L, D)
        return self.out_proj(out)

class ConvDistiller(nn.Module):
    """Self-attention distilling — сжатие последовательности"""
    def __init__(self, d_model):
        super().__init__()
        self.conv = nn.Sequential(nn.Conv1d(d_model, d_model, 3, padding=1), nn.ELU(), nn.MaxPool1d(2, stride=2))
        self.norm = nn.LayerNorm(d_model)
    
    def forward(self, x):
        x = self.conv(x.transpose(1,2)).transpose(1,2)
        return self.norm(x)

class InformerBlock(nn.Module):
    def __init__(self, d_model, n_heads=8, distill=True):
        super().__init__()
        self.attention = ProbSparseAttention(d_model, n_heads)
        self.distiller = ConvDistiller(d_model) if distill else nn.Identity()
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.ff = nn.Sequential(nn.Linear(d_model, d_model*4), nn.GELU(), nn.Linear(d_model*4, d_model))
        self.dropout = nn.Dropout(0.1)
    
    def forward(self, x):
        x = x + self.dropout(self.attention(self.norm1(x)))
        x = self.distiller(x)
        x = x + self.dropout(self.ff(self.norm2(x)))
        return x

class InformerDetector(nn.Module):
    def __init__(self, input_dim=76, d_model=256, num_layers=3, num_classes=2):
        super().__init__()
        self.embed = nn.Linear(input_dim, d_model)
        self.blocks = nn.ModuleList([InformerBlock(d_model, distill=(i < num_layers-1)) for i in range(num_layers)])
        self.head = nn.Linear(d_model, num_classes)
    
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        x = self.embed(x)
        for block in self.blocks: x = block(x)
        return self.head(x.mean(dim=1))

class InformerWrapper:
    def __init__(self, input_dim=76):
        self.model = InformerDetector(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.0001)
        X_t, y_t = torch.FloatTensor(X).to(self.device), torch.LongTensor(y).to(self.device)
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

logger.info("✅ Informer ready (#44)")

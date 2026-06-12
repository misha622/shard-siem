"""SHARD Wide & Deep (#48) — Комбинация линейной + глубокой модели"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-WideDeep")

class WideAndDeep(nn.Module):
    def __init__(self, input_dim=76, deep_dims=[128, 64, 32], num_classes=2):
        super().__init__()
        self.wide = nn.Linear(input_dim, num_classes)
        deep_layers = []
        prev = input_dim
        for d in deep_dims:
            deep_layers += [nn.Linear(prev, d), nn.ReLU(), nn.BatchNorm1d(d), nn.Dropout(0.2)]
            prev = d
        self.deep = nn.Sequential(*deep_layers)
        self.deep_head = nn.Linear(deep_dims[-1], num_classes)
    
    def forward(self, x):
        wide_out = self.wide(x)
        deep_out = self.deep_head(self.deep(x))
        return wide_out + deep_out

class WideDeepWrapper:
    def __init__(self, input_dim=76):
        self.model = WideAndDeep(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
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

logger.info("✅ Wide & Deep ready (#48)")

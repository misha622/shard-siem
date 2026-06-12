"""SHARD DeepFM (#49) — Factorization Machines + Deep Neural Network"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-DeepFM")

class DeepFM(nn.Module):
    def __init__(self, input_dim=76, embed_dim=16, deep_dims=[128, 64, 32], num_classes=2):
        super().__init__()
        # FM часть
        self.fm_linear = nn.Linear(input_dim, 1)
        self.fm_embed = nn.ModuleList([nn.Linear(1, embed_dim) for _ in range(input_dim)])
        # Deep часть
        deep_layers = [nn.Linear(input_dim, deep_dims[0]), nn.ReLU(), nn.BatchNorm1d(deep_dims[0])]
        for i in range(len(deep_dims)-1):
            deep_layers += [nn.Linear(deep_dims[i], deep_dims[i+1]), nn.ReLU(), nn.BatchNorm1d(deep_dims[i+1])]
        self.deep = nn.Sequential(*deep_layers)
        self.head = nn.Linear(1 + embed_dim + deep_dims[-1], num_classes)
    
    def forward(self, x):
        # Linear
        linear = self.fm_linear(x)
        # FM взаимодействия
        embeds = torch.stack([self.fm_embed[i](x[:, i:i+1]) for i in range(x.size(1))], dim=1)
        sum_square = embeds.sum(dim=1) ** 2
        square_sum = (embeds ** 2).sum(dim=1)
        fm = 0.5 * (sum_square - square_sum).sum(dim=1, keepdim=True)
        # Deep
        deep = self.deep(x)
        return self.head(torch.cat([linear, fm, deep], dim=-1))

class DeepFMWrapper:
    def __init__(self, input_dim=76):
        self.model = DeepFM(input_dim)
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

logger.info("✅ DeepFM ready (#49)")

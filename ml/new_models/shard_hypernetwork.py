"""SHARD HyperNetwork (#40) — одна сеть генерирует веса для другой"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-HyperNetwork")

class HyperNetwork(nn.Module):
    def __init__(self, input_dim=76, latent_dim=64, main_hidden=128, num_classes=2):
        super().__init__()
        self.latent = nn.Parameter(torch.randn(1, latent_dim))
        self.hyper = nn.Sequential(nn.Linear(latent_dim, 256), nn.ReLU(), nn.Linear(256, main_hidden * input_dim + main_hidden))
        self.bias_hyper = nn.Sequential(nn.Linear(latent_dim, 128), nn.ReLU(), nn.Linear(128, main_hidden + num_classes))
        self.main_hidden = main_hidden
        self.input_dim = input_dim
        self.num_classes = num_classes
    
    def forward(self, x):
        weights = self.hyper(self.latent)
        w1 = weights[:, :self.main_hidden * self.input_dim].view(self.main_hidden, self.input_dim)
        b1 = self.bias_hyper(self.latent)[:, :self.main_hidden]
        h = F.relu(F.linear(x, w1, b1))
        w2 = torch.randn(self.num_classes, self.main_hidden, device=x.device)
        b2 = self.bias_hyper(self.latent)[:, self.main_hidden:]
        return F.linear(h, w2, b2)

class HyperNetworkDetector:
    def __init__(self, input_dim=76):
        self.model = HyperNetwork(input_dim)
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

logger.info("✅ HyperNetwork ready (#40)")

"""SHARD DeepSVDD — глубокая one-class классификация (#30)"""
import numpy as np, torch, torch.nn as nn, logging
logger = logging.getLogger("SHARD-DeepSVDD")

class DeepSVDDNet(nn.Module):
    def __init__(self, input_dim=76, hidden_dims=[128,64,32]):
        super().__init__()
        layers = []
        prev = input_dim
        for h in hidden_dims:
            layers += [nn.Linear(prev, h), nn.ReLU(), nn.BatchNorm1d(h)]
            prev = h
        self.encoder = nn.Sequential(*layers)
    def forward(self, x): return self.encoder(x)

class DeepSVDDDetector:
    def __init__(self, input_dim=76):
        self.model = DeepSVDDNet(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.center = None
        self.radius = 0.0
        self.is_trained = False
    
    def train(self, X_normal, epochs=50):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X_normal).to(self.device)
        # Init center
        with torch.no_grad():
            self.center = self.model(X_t).mean(dim=0)
        for _ in range(epochs):
            opt.zero_grad()
            z = self.model(X_t)
            loss = ((z - self.center) ** 2).mean()
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            dists = ((self.model(X_t) - self.center) ** 2).sum(dim=1).cpu().numpy()
            self.radius = np.percentile(dists, 95)
        self.is_trained = True
        return {'radius': float(self.radius)}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            dists = ((self.model(X_t) - self.center) ** 2).sum(dim=1).cpu().numpy()
        scores = np.clip(dists / (self.radius + 1e-8), 0, 2)
        return (scores > 1.0).astype(int), scores / 2.0

logger.info("✅ DeepSVDD ready (#30)")

"""SHARD SimCLR (#50) — Contrastive Learning для кибербезопасности"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-SimCLR")

class SimCLR(nn.Module):
    def __init__(self, input_dim=76, projection_dim=64, temperature=0.1):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(input_dim, 128), nn.ReLU(), nn.Linear(128, projection_dim))
        self.projection = nn.Sequential(nn.Linear(projection_dim, 64), nn.ReLU(), nn.Linear(64, 32))
        self.temperature = temperature
    
    def forward(self, x1, x2):
        z1 = F.normalize(self.projection(self.encoder(x1)), dim=-1)
        z2 = F.normalize(self.projection(self.encoder(x2)), dim=-1)
        return z1, z2
    
    def contrastive_loss(self, z1, z2):
        z = torch.cat([z1, z2], dim=0)
        sim = torch.matmul(z, z.T) / self.temperature
        labels = torch.cat([torch.arange(z1.size(0)) for _ in range(2)], dim=0).to(z.device)
        mask = torch.eye(labels.size(0), device=z.device).bool()
        sim = sim.masked_fill(mask, -float('inf'))
        return F.cross_entropy(sim, labels)

class SimCLRDetector:
    def __init__(self, input_dim=76):
        self.model = SimCLR(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.normal_center = None
        self.threshold = 0.0
        self.is_trained = False
    
    def train(self, X, y=None, epochs=50):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X).to(self.device)
        for _ in range(epochs):
            # Аугментации
            noise = torch.randn_like(X_t) * 0.05
            mask = torch.rand_like(X_t) > 0.1
            x1 = X_t + noise
            x2 = X_t * mask.float()
            opt.zero_grad()
            z1, z2 = self.model(x1, x2)
            loss = self.model.contrastive_loss(z1, z2)
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            embeddings = self.model.encoder(X_t)
            self.normal_center = embeddings.mean(dim=0)
            dists = torch.norm(embeddings - self.normal_center, dim=1)
            self.threshold = np.percentile(dists.cpu().numpy(), 95)
        self.is_trained = True
        return {'threshold': float(self.threshold)}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            embeddings = self.model.encoder(X_t)
            scores = torch.norm(embeddings - self.normal_center, dim=1).cpu().numpy()
        scores = np.clip(scores / (self.threshold + 1e-8), 0, 2)
        return (scores > 1.0).astype(int), scores / 2.0

logger.info("✅ SimCLR ready (#50)")

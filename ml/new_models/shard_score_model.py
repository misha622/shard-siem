"""SHARD Score-Based / Diffusion Model (#36)"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-ScoreModel")

class ScoreNet(nn.Module):
    def __init__(self, dim=76, hidden=256):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(dim+1, hidden), nn.SiLU(), nn.Linear(hidden, hidden), nn.SiLU(), nn.Linear(hidden, dim))
    def forward(self, x, t):
        t_emb = t.unsqueeze(1).expand(-1, x.size(1))
        return self.net(torch.cat([x, t_emb], dim=-1))

class ScoreBasedDetector:
    def __init__(self, input_dim=76):
        self.model = ScoreNet(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    
    def train(self, X, epochs=50):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            t = torch.rand(len(X_t), 1, device=self.device)
            noise = torch.randn_like(X_t)
            x_noisy = X_t + t * noise
            score = self.model(x_noisy, t.squeeze())
            loss = F.mse_loss(score, -noise / (t + 1e-8))
            loss.backward()
            opt.step()
        self.is_trained = True
        return {'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            scores = torch.norm(self.model(X_t, torch.ones(len(X_t), device=self.device)), dim=1).cpu().numpy()
        scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return (scores > 0.5).astype(int), scores

logger.info("✅ Score-Based Model ready (#36)")

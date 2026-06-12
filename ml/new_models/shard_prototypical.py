"""SHARD Prototypical Network (#41) — Few-shot detection новых атак"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-ProtoNet")

class ProtoNet(nn.Module):
    def __init__(self, input_dim=76, embedding_dim=64):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(input_dim, 128), nn.ReLU(), nn.Linear(128, embedding_dim))
    def forward(self, x): return self.encoder(x)

class PrototypicalDetector:
    def __init__(self, input_dim=76):
        self.model = ProtoNet(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.prototypes = {}
        self.is_trained = False
    
    def train(self, X, y, epochs=50):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t, y_t = torch.FloatTensor(X).to(self.device), torch.LongTensor(y).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            embeddings = self.model(X_t)
            unique_y = torch.unique(y_t)
            prototypes = torch.stack([embeddings[y_t==c].mean(0) for c in unique_y])
            dists = torch.cdist(embeddings, prototypes)
            loss = -F.log_softmax(-dists, dim=1).gather(1, y_t.unsqueeze(1)).mean()
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            embs = self.model(X_t)
            for c in torch.unique(y_t): self.prototypes[int(c)] = embs[y_t==c].mean(0)
        self.is_trained = True
        return {'prototypes': len(self.prototypes)}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            embs = self.model(X_t)
            proto = torch.stack(list(self.prototypes.values()))
            dists = torch.cdist(embs, proto)
            scores = 1 - F.softmax(-dists, dim=1)[:, 0].cpu().numpy()
        return (scores > 0.5).astype(int), scores

logger.info("✅ Prototypical Network ready (#41)")

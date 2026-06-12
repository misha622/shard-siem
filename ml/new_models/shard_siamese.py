"""SHARD Siamese Network (#42) — Сравнение пар для детекции"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-Siamese")

class SiameseNetwork(nn.Module):
    def __init__(self, input_dim=76, embedding_dim=64):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(input_dim, 128), nn.ReLU(), nn.Dropout(0.2), nn.Linear(128, embedding_dim))
    def forward(self, x1, x2):
        e1, e2 = self.encoder(x1), self.encoder(x2)
        return F.pairwise_distance(e1, e2)

class SiameseDetector:
    def __init__(self, input_dim=76):
        self.model = SiameseNetwork(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.normal_embeddings = None
        self.is_trained = False
    
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        for _ in range(epochs):
            idx1, idx2 = torch.randint(0, len(X_t), (len(X_t)//2,)), torch.randint(0, len(X_t), (len(X_t)//2,))
            same = y_t[idx1] == y_t[idx2]
            opt.zero_grad()
            dist = self.model(X_t[idx1], X_t[idx2])
            loss = F.binary_cross_entropy(torch.exp(-dist), same.float())
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad(): self.normal_embeddings = self.model.encoder(X_t[y_t==0][:100]).cpu()
        self.is_trained = True
        return {'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            embs = self.model.encoder(X_t)
            ref = self.normal_embeddings[:10].to(self.device)
            scores = torch.cdist(embs, ref).min(dim=1)[0].cpu().numpy()
        scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return (scores > 0.5).astype(int), scores

logger.info("✅ Siamese Network ready (#42)")

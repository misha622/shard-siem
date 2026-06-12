"""SHARD DeepAR (#47) — Probabilistic forecasting с оценкой неопределённости"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-DeepAR")

class DeepAR(nn.Module):
    def __init__(self, input_dim=76, hidden_dim=128, num_layers=2, num_classes=2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.mu_head = nn.Linear(hidden_dim, num_classes)
        self.sigma_head = nn.Sequential(nn.Linear(hidden_dim, num_classes), nn.Softplus())
    
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        out, _ = self.lstm(x)
        mu = self.mu_head(out[:, -1, :])
        sigma = self.sigma_head(out[:, -1, :])
        return mu, sigma

class DeepARWrapper:
    def __init__(self, input_dim=76):
        self.model = DeepAR(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t, y_t = torch.FloatTensor(X).to(self.device), torch.LongTensor(y).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            mu, sigma = self.model(X_t)
            loss = F.gaussian_nll_loss(mu, y_t.unsqueeze(1).float().expand_as(mu), sigma**2)
            loss.backward()
            opt.step()
        self.is_trained = True
        return {'epochs': epochs}
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            mu, sigma = self.model(X_t)
            probs = F.softmax(mu, dim=-1)[:,1].cpu().numpy()
            uncertainty = sigma[:,1].cpu().numpy()
        return (probs>0.5).astype(int), probs

logger.info("✅ DeepAR ready (#47)")

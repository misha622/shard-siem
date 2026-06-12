"""SHARD N-BEATS (#46) — Neural Basis Expansion Analysis"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-NBEATS")

class NBEATSBlock(nn.Module):
    def __init__(self, input_dim, hidden_dim=256, theta_dim=8):
        super().__init__()
        self.fc = nn.Sequential(nn.Linear(input_dim, hidden_dim), nn.ReLU(), nn.Linear(hidden_dim, hidden_dim), nn.ReLU(), nn.Linear(hidden_dim, hidden_dim), nn.ReLU(), nn.Linear(hidden_dim, theta_dim*2))
        self.theta_dim = theta_dim
    
    def forward(self, x):
        theta = self.fc(x)
        backcast, forecast = theta[:, :self.theta_dim], theta[:, self.theta_dim:]
        return backcast, forecast

class NBEATS(nn.Module):
    def __init__(self, input_dim=76, num_blocks=3, num_classes=2):
        super().__init__()
        self.blocks = nn.ModuleList([NBEATSBlock(input_dim) for _ in range(num_blocks)])
        self.head = nn.Linear(input_dim, num_classes)
    
    def forward(self, x):
        residuals = x
        forecast_sum = 0
        for block in self.blocks:
            backcast, forecast = block(residuals)
            residuals = residuals - backcast
            forecast_sum = forecast_sum + forecast
        return self.head(residuals + forecast_sum)

class NBEATSWrapper:
    def __init__(self, input_dim=76):
        self.model = NBEATS(input_dim)
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

logger.info("✅ N-BEATS ready (#46)")

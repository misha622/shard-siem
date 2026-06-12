"""SHARD Neural ODE (#35) — Continuous-time model (pure PyTorch)"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-NeuralODE")

class ODEFunc(nn.Module):
    def __init__(self, dim):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(dim, dim*2), nn.Tanh(), nn.Linear(dim*2, dim))
    def forward(self, x):
        return self.net(x)

class NeuralODEDetector(nn.Module):
    def __init__(self, input_dim=76, hidden_dim=64, num_steps=3):
        super().__init__()
        self.encoder = nn.Linear(input_dim, hidden_dim)
        self.ode_func = ODEFunc(hidden_dim)
        self.decoder = nn.Linear(hidden_dim, input_dim)
        self.num_steps = num_steps
        self.dt = 0.1
    
    def forward(self, x):
        h = self.encoder(x)
        for _ in range(self.num_steps):
            h = h + self.dt * self.ode_func(h)
        return self.decoder(h)

class NeuralODEDetectorWrapper:
    def __init__(self, input_dim=76):
        self.model = NeuralODEDetector(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.threshold = 0.0
        self.is_trained = False
    
    def train(self, X, epochs=50):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            loss = F.mse_loss(self.model(X_t), X_t)
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            errors = ((self.model(X_t) - X_t) ** 2).mean(dim=1).cpu().numpy()
            self.threshold = np.percentile(errors, 95)
        self.is_trained = True
        return {'threshold': float(self.threshold)}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            errors = ((self.model(X_t) - X_t) ** 2).mean(dim=1).cpu().numpy()
        scores = np.clip(errors / (self.threshold + 1e-8), 0, 2)
        return (scores > 1.0).astype(int), scores / 2.0

logger.info("✅ Neural ODE ready (#35)")

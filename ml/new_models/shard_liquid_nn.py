"""SHARD Liquid Neural Network (#39) — адаптивные дифференциальные уравнения"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-LiquidNN")

class LiquidLayer(nn.Module):
    def __init__(self, dim):
        super().__init__()
        self.W = nn.Parameter(torch.randn(dim, dim))
        self.A = nn.Parameter(torch.randn(dim, dim))
        self.tau = nn.Parameter(torch.ones(1))
        self.bias = nn.Parameter(torch.zeros(dim))
    def forward(self, x, h=None):
        if h is None: h = torch.zeros(x.size(0), x.size(-1), device=x.device)
        dh = -h / self.tau + torch.tanh(F.linear(x, self.W) + F.linear(h, self.A) + self.bias)
        return h + dh

class LiquidNN(nn.Module):
    def __init__(self, input_dim=76, hidden_dim=64, num_layers=3, num_classes=2):
        super().__init__()
        self.embed = nn.Linear(input_dim, hidden_dim)
        self.liquid_layers = nn.ModuleList([LiquidLayer(hidden_dim) for _ in range(num_layers)])
        self.head = nn.Linear(hidden_dim, num_classes)
    def forward(self, x):
        h = F.silu(self.embed(x))
        for layer in self.liquid_layers: h = layer(h)
        return self.head(h)

class LiquidNNDetector:
    def __init__(self, input_dim=76):
        self.model = LiquidNN(input_dim)
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

logger.info("✅ Liquid NN ready (#39)")

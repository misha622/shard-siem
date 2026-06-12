"""SHARD KAN — Kolmogorov-Arnold Network (#38)"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-KAN")

class KANLinear(nn.Module):
    def __init__(self, in_features, out_features, grid_size=5, spline_order=3):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.base_weight = nn.Parameter(torch.Tensor(out_features, in_features))
        self.spline_weight = nn.Parameter(torch.Tensor(out_features, in_features, grid_size + spline_order))
        self.grid = nn.Parameter(torch.linspace(-1, 1, grid_size + spline_order + 1).expand(in_features, -1), requires_grad=False)
        nn.init.kaiming_uniform_(self.base_weight, a=5**0.5)
        nn.init.kaiming_uniform_(self.spline_weight, a=5**0.5)
    
    def forward(self, x):
        base = F.linear(x, self.base_weight)
        x_expanded = x.unsqueeze(-1)
        grid = self.grid.unsqueeze(0)
        basis = F.relu(x_expanded - grid[:, :-1]) ** 3 - 3 * F.relu(x_expanded - grid[:, 1:-1]) ** 3 + 3 * F.relu(x_expanded - grid[:, 2:]) ** 3 - F.relu(x_expanded - grid[:, 3:]) ** 3
        spline = torch.einsum('bik,oik->bo', basis, self.spline_weight)
        return base + spline

class KAN(nn.Module):
    def __init__(self, layers=[76, 64, 32, 2]):
        super().__init__()
        self.layers = nn.ModuleList([KANLinear(layers[i], layers[i+1]) for i in range(len(layers)-1)])
    def forward(self, x):
        for layer in self.layers[:-1]: x = F.silu(layer(x))
        return self.layers[-1](x)

class KANDetector:
    def __init__(self, input_dim=76):
        self.model = KAN([input_dim, 64, 32, 2])
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

logger.info("✅ KAN ready (#38)")

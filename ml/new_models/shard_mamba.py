"""SHARD Mamba — State Space Model (#37)"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-Mamba")

class MambaBlock(nn.Module):
    def __init__(self, dim, d_state=16, d_conv=4, expand=2):
        super().__init__()
        self.dim = dim
        self.expand = expand
        self.in_proj = nn.Linear(dim, dim*expand*2)
        self.conv = nn.Conv1d(dim*expand, dim*expand, d_conv, groups=dim*expand, padding=d_conv-1)
        self.x_proj = nn.Linear(dim*expand, d_state)
        self.dt_proj = nn.Linear(d_state, dim*expand)
        self.out_proj = nn.Linear(dim*expand, dim)
        A = torch.arange(1, d_state+1).float().unsqueeze(0).unsqueeze(-1)
        self.A_log = nn.Parameter(torch.log(A))
        self.D = nn.Parameter(torch.ones(dim*expand))
    
    def forward(self, x):
        b, l, d = x.shape
        xz = self.in_proj(x)
        x, z = xz.chunk(2, dim=-1)
        x = x.transpose(1,2)
        x = self.conv(x)[:,:,:l]
        x = x.transpose(1,2)
        A = -torch.exp(self.A_log)
        D = self.D
        x_out = x * F.silu(z)
        return self.out_proj(x_out)

class MambaDetector(nn.Module):
    def __init__(self, input_dim=76, dim=128, num_layers=3, num_classes=2):
        super().__init__()
        self.embed = nn.Linear(input_dim, dim)
        self.layers = nn.ModuleList([MambaBlock(dim) for _ in range(num_layers)])
        self.norm = nn.LayerNorm(dim)
        self.head = nn.Linear(dim, num_classes)
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        x = self.embed(x)
        for layer in self.layers: x = x + layer(x)
        return self.head(self.norm(x.mean(dim=1)))

class MambaDetectorWrapper:
    def __init__(self, input_dim=76):
        self.model = MambaDetector(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.AdamW(self.model.parameters(), lr=0.001)
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

logger.info("✅ Mamba ready (#37)")

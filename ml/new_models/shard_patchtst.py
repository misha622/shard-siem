"""SHARD PatchTST (#45) — Патчи как токены для временных рядов"""
import numpy as np, logging, torch, torch.nn as nn, torch.nn.functional as F
logger = logging.getLogger("SHARD-PatchTST")

class PatchTST(nn.Module):
    def __init__(self, input_dim=76, patch_len=16, stride=8, d_model=128, n_heads=8, num_layers=3, num_classes=2):
        super().__init__()
        self.patch_len = patch_len
        self.stride = stride
        self.patch_embed = nn.Linear(patch_len, d_model)
        self.pos_embed = nn.Parameter(torch.randn(1, 100, d_model))
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=n_heads, dropout=0.1, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.head = nn.Linear(d_model, num_classes)
    
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        B, L, F = x.shape
        patches = x.unfold(1, self.patch_len, self.stride)  # (B, n_patches, F, patch_len)
        patches = patches.reshape(B, -1, self.patch_len)
        x = self.patch_embed(patches)
        x = x + self.pos_embed[:, :x.size(1), :]
        x = self.transformer(x)
        return self.head(x.mean(dim=1))

class PatchTSTWrapper:
    def __init__(self, input_dim=76):
        self.model = PatchTST(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.0001)
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

logger.info("✅ PatchTST ready (#45)")

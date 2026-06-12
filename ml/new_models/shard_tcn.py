"""SHARD TCN — Temporal Convolutional Network (#29)"""
import numpy as np, torch, torch.nn as nn, logging
logger = logging.getLogger("SHARD-TCN")

class TCN(nn.Module):
    def __init__(self, input_dim=76, num_channels=[64,64,64], kernel_size=3, dropout=0.2):
        super().__init__()
        layers = []
        in_channels = input_dim
        for out_channels in num_channels:
            layers += [
                nn.Conv1d(in_channels, out_channels, kernel_size, padding=kernel_size//2),
                nn.ReLU(), nn.BatchNorm1d(out_channels), nn.Dropout(dropout)
            ]
            in_channels = out_channels
        self.network = nn.Sequential(*layers)
        self.fc = nn.Linear(num_channels[-1], 2)
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1).transpose(1,2)
        if x.dim() == 2: x = x.unsqueeze(1)
        out = self.network(x)
        return self.fc(out.mean(dim=-1))

class TCNDetector:
    def __init__(self, input_dim=76):
        self.model = TCN(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            loss = nn.CrossEntropyLoss()(self.model(X_t), y_t)
            loss.backward()
            opt.step()
        self.is_trained = True
        return {'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            probs = torch.softmax(self.model(X_t), dim=-1)[:, 1].cpu().numpy()
        return (probs > 0.5).astype(int), probs

logger.info("✅ TCN ready (#29)")

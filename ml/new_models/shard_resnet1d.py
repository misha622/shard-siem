"""SHARD ResNet1D — глубокая CNN с skip-connections (#28)"""
import numpy as np, torch, torch.nn as nn, logging
logger = logging.getLogger("SHARD-ResNet1D")

class ResidualBlock(nn.Module):
    def __init__(self, in_dim, out_dim, kernel_size=3):
        super().__init__()
        self.conv1 = nn.Conv1d(in_dim, out_dim, kernel_size, padding=1)
        self.bn1 = nn.BatchNorm1d(out_dim)
        self.conv2 = nn.Conv1d(out_dim, out_dim, kernel_size, padding=1)
        self.bn2 = nn.BatchNorm1d(out_dim)
        self.skip = nn.Conv1d(in_dim, out_dim, 1) if in_dim != out_dim else nn.Identity()
    def forward(self, x):
        residual = self.skip(x)
        out = torch.relu(self.bn1(self.conv1(x)))
        out = self.bn2(self.conv2(out))
        return torch.relu(out + residual)

class ResNet1D(nn.Module):
    def __init__(self, input_dim=76, num_classes=2):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 32, 7, padding=3)
        self.bn1 = nn.BatchNorm1d(32)
        self.res1 = ResidualBlock(32, 64)
        self.res2 = ResidualBlock(64, 128)
        self.pool = nn.AdaptiveAvgPool1d(8)
        self.fc = nn.Linear(128*8, num_classes)
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        x = torch.relu(self.bn1(self.conv1(x)))
        x = self.res1(x)
        x = self.res2(x)
        x = self.pool(x)
        return self.fc(x.view(x.size(0), -1))

class ResNet1DDetector:
    def __init__(self, input_dim=76):
        self.model = ResNet1D(input_dim)
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

logger.info("✅ ResNet1D ready (#28)")

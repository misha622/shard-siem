"""SHARD BiLSTM — двунаправленная LSTM (#25)"""
import numpy as np, torch, torch.nn as nn, logging
logger = logging.getLogger("SHARD-BiLSTM")

class BiLSTM(nn.Module):
    def __init__(self, input_dim=76, hidden_dim=64, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, bidirectional=True)
        self.fc = nn.Sequential(nn.Linear(hidden_dim*2, 32), nn.ReLU(), nn.Dropout(0.3), nn.Linear(32, 2))
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

class BiLSTMDetector:
    def __init__(self, input_dim=76):
        self.model = BiLSTM(input_dim)
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

logger.info("✅ BiLSTM ready (#25)")

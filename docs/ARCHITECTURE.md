# SHARD Architecture

## System Overview
┌─────────────────────────────┐
│ 13 Honeypots │
│ SSH, MySQL, Redis, FTP... │
└──────────┬──────────────────┘
│
┌──────────▼──────────────────┐
│ ML Classifier (XGBoost) │
│ 13 attack types │
└──────────┬──────────────────┘
│
┌────────────────────┼────────────────────┐
│ │ │
┌─────────▼────────┐ ┌───────▼────────┐ ┌───────▼────────┐
│ Seq2Seq Defense │ │ RL DQN Agent │ │ VAE Anomaly │
│ (5.35M params) │ │ (block/perm) │ │ Detector │
└─────────┬────────┘ └───────┬────────┘ └───────┬────────┘
│ │ │
└────────────────────┼────────────────────┘
│
┌──────────▼──────────────────┐
│ Multi-Modal Fusion │
│ (Cross-Attention) │
└──────────┬──────────────────┘
│
┌────────────────────┼────────────────────┐
│ │ │
┌─────────▼────────┐ ┌───────▼────────┐ ┌───────▼────────┐
│ GNN Threat │ │ Temporal │ │ Federated │
│ Graph │ │ GNN Predict │ │ Learning │
└──────────────────┘ └────────────────┘ └────────────────┘

## Neural Networks

| # | Model | Parameters | Accuracy | Purpose |
|---|-------|-----------|----------|---------|
| 1 | XGBoost | 500 trees | 100% | Attack classification |
| 2 | Seq2Seq Transformer | 5.35M | Code Gen | Defense rule generation |
| 3 | RL DQN Agent | ~50K | 100% | Autonomous blocking |
| 4 | VAE | 128K | 91.2% | Zero-day detection |
| 5 | GNN (GCN+GAT) | 103K | 100% | Threat graph analysis |
| 6 | Multi-Modal Fusion | 226K | 100% | Cross-attention ensemble |
| 7 | Federated Learning | ~50K | 85.4% | Privacy-preserving training |
| 8 | Temporal GNN | 105K | 75% | Attack prediction |

## Data Flow

1. **Packet Capture** → TrafficAnalyzer
2. **Feature Extraction** → ML Pipeline  
3. **Classification** → XGBoost (13 types)
4. **Defense Generation** → Seq2Seq Transformer
5. **Action Decision** → RL DQN Agent
6. **Anomaly Check** → VAE Detector
7. **Threat Mapping** → GNN Graph
8. **Prediction** → Temporal GNN
9. **Fusion** → Multi-Modal Attention
10. **Notification** → Telegram/Slack

## Deployment

```bash
docker run -d -p 8080:8080 -p 5001:5001 shard19/shard-siem

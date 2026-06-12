"""SHARD New Models Package — 30 моделей"""
# Базовые
from ml.new_models.shard_lightgbm import LightGBMDetector
from ml.new_models.shard_catboost import CatBoostDetector

# Аномалии
from ml.new_models.shard_oneclass_svm import OneClassSVMDetector
from ml.new_models.shard_knn import KNNDetector
from ml.new_models.shard_ecod import ECODDetector
from ml.new_models.shard_hdbscan import HDBSCANDetector
from ml.new_models.shard_umap_iforest import UMAPIForestDetector
from ml.new_models.shard_deep_ae import DeepAEDetector
from ml.new_models.shard_attention_ae import AttentionAEDetector
from ml.new_models.shard_deep_svdd import DeepSVDDDetector
from ml.new_models.shard_anomaly_transformer import AnomalyTransformerDetector

# Графовые
from ml.new_models.shard_gat_v2 import GATv2Detector
from ml.new_models.shard_graph_autoencoder import GraphAEDetector

# Глубокое обучение
from ml.new_models.shard_bayesian_nn import BayesianNNDetector
from ml.new_models.shard_cnn1d import CNN1DWrapper
from ml.new_models.shard_bilstm import BiLSTMDetector
from ml.new_models.shard_gru import GRUDetector
from ml.new_models.shard_resnet1d import ResNet1DDetector
from ml.new_models.shard_tcn import TCNDetector
from ml.new_models.shard_ft_transformer import FTTransformerDetector
from ml.new_models.shard_mamba import MambaDetectorWrapper
from ml.new_models.shard_kan import KANDetector
from ml.new_models.shard_liquid_nn import LiquidNNDetector
from ml.new_models.shard_hypernetwork import HyperNetworkDetector
from ml.new_models.shard_tabnet import TabNetWrapper

# Временные ряды
from ml.new_models.shard_autoformer import AutoformerWrapper
from ml.new_models.shard_informer import InformerWrapper
from ml.new_models.shard_patchtst import PatchTSTWrapper
from ml.new_models.shard_nbeats import NBEATSWrapper
from ml.new_models.shard_deepar import DeepARWrapper
from ml.new_models.shard_neural_ode import NeuralODEDetectorWrapper

# Контрастные / Мета
from ml.new_models.shard_simclr import SimCLRDetector
from ml.new_models.shard_prototypical import PrototypicalDetector
from ml.new_models.shard_siamese import SiameseDetector
from ml.new_models.shard_score_model import ScoreBasedDetector

# Гибридные
from ml.new_models.shard_wide_deep import WideDeepWrapper
from ml.new_models.shard_deepfm import DeepFMWrapper

# Ансамбли
from ml.new_models.shard_ensemble_voting import VotingEnsemble

__all__ = [
    'LightGBMDetector', 'CatBoostDetector',
    'OneClassSVMDetector', 'KNNDetector', 'ECODDetector', 'HDBSCANDetector',
    'UMAPIForestDetector', 'DeepAEDetector', 'AttentionAEDetector', 'DeepSVDDDetector',
    'AnomalyTransformerDetector', 'GATv2Detector', 'GraphAEDetector',
    'BayesianNNDetector', 'CNN1DWrapper', 'BiLSTMDetector', 'GRUDetector',
    'ResNet1DDetector', 'TCNDetector', 'FTTransformerDetector', 'MambaDetectorWrapper',
    'KANDetector', 'LiquidNNDetector', 'HyperNetworkDetector', 'TabNetWrapper',
    'AutoformerWrapper', 'InformerWrapper', 'PatchTSTWrapper', 'NBEATSWrapper',
    'DeepARWrapper', 'NeuralODEDetectorWrapper',
    'SimCLRDetector', 'PrototypicalDetector', 'SiameseDetector', 'ScoreBasedDetector',
    'WideDeepWrapper', 'DeepFMWrapper', 'VotingEnsemble',
]

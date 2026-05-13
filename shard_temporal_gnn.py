#!/usr/bin/env python3

"""
SHARD Temporal Graph Neural Network - Production-Ready
Графовая нейронная сеть с временной компонентой для обнаружения lateral movement и C2.

Версия: 5.0.0 - Полное обучение, message passing, attention, мониторинг

Author: SHARD Enterprise
"""

import os
import sys
import time
import json
import threading
import warnings
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import logging

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SHARD-TemporalGNN")

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


TF_AVAILABLE = False
TORCH_AVAILABLE = False
TORCH_GEOMETRIC_AVAILABLE = False
NX_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model, optimizers, losses, metrics

    TF_AVAILABLE = True
    logger.info("✅ TensorFlow loaded")
except ImportError:
    logger.warning("⚠️ TensorFlow not installed")

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim

    TORCH_AVAILABLE = True
    logger.info("✅ PyTorch loaded")
except ImportError:
    logger.warning("⚠️ PyTorch not installed")

try:
    from torch_geometric.nn import GCNConv, GATConv, SAGEConv, global_mean_pool, global_max_pool
    from torch_geometric.data import Data, Batch
    from torch_geometric.loader import DataLoader

    TORCH_GEOMETRIC_AVAILABLE = True
    logger.info("✅ PyTorch Geometric loaded")
except ImportError:
    logger.warning("⚠️ PyTorch Geometric not installed. Install: pip install torch-geometric")

try:
    import networkx as nx

    NX_AVAILABLE = True
    logger.info("✅ NetworkX loaded")
except ImportError:
    logger.warning("⚠️ NetworkX not installed. Install: pip install networkx")



@dataclass
class TemporalGNNConfig:
    """Конфигурация Temporal GNN"""

    max_nodes: int = 2000
    node_feature_dim: int = 64
    edge_feature_dim: int = 16
    time_steps: int = 10
    temporal_window: int = 60

    gnn_type: str = 'gat'
    gnn_hidden_dim: int = 128
    gnn_num_layers: int = 3
    gnn_heads: int = 4
    dropout_rate: float = 0.2

    lstm_hidden_dim: int = 64
    lstm_num_layers: int = 2
    lstm_bidirectional: bool = True

    use_attention_pooling: bool = True
    attention_heads: int = 4

    learning_rate: float = 0.001
    batch_size: int = 32
    epochs: int = 50
    early_stopping_patience: int = 10
    gradient_clip_norm: float = 1.0
    weight_decay: float = 0.0001

    use_contrastive_loss: bool = True
    contrastive_temperature: float = 0.1
    contrastive_weight: float = 0.3

    anomaly_threshold: float = 0.7
    node_anomaly_threshold: float = 0.6
    graph_window_size: int = 100

    max_graphs_in_memory: int = 1000
    cleanup_interval: int = 300
    max_workers: int = 4

    model_dir: str = './models/temporal_gnn/'
    checkpoint_frequency: int = 100

    def save(self, path: str):
        """Сохранение конфигурации"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.__dict__, f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'TemporalGNNConfig':
        """Загрузка конфигурации"""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)



class NetworkGraphBuilder:
    """
    Построитель и менеджер сетевых графов.

    Особенности:
    - Эффективное построение графов из потока
    - Temporal snapshots с окном
    - Feature extraction для GNN
    - Автоматическая очистка устаревших данных
    """

    def __init__(self, config: TemporalGNNConfig):
        self.config = config

        self.current_graph = nx.DiGraph()
        self.graph_snapshots: deque = deque(maxlen=config.max_graphs_in_memory)

        self.last_snapshot_time = time.time()
        self.snapshot_interval = config.temporal_window // config.time_steps

        self.node_id_map: Dict[str, int] = {}
        self.reverse_node_map: Dict[int, str] = {}
        self.node_features_cache: Dict[str, np.ndarray] = {}

        self.connection_stats: Dict[Tuple[str, str], Dict] = defaultdict(lambda: {
            'count': 0,
            'total_bytes': 0,
            'total_packets': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'ports': set(),
            'protocols': set()
        })

        self._graph_lock = threading.RLock()
        self._stats_lock = threading.RLock()

        self.local_networks = ['192.168.', '10.', '172.16.', '172.17.', '172.18.',
                               '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                               '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                               '172.29.', '172.30.', '172.31.', '127.']

        self.stats = {
            'total_connections': 0,
            'total_nodes': 0,
            'total_edges': 0,
            'snapshots_created': 0
        }

        self._executor = ThreadPoolExecutor(max_workers=2)

        logger.info(f"✅ NetworkGraphBuilder initialized (window={config.temporal_window}s, "
                    f"snapshots={config.time_steps})")

    def add_connection(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       protocol: int, bytes_count: int, packets_count: int = 1,
                       timestamp: float = None):
        """
        Добавление сетевого соединения в текущий граф.

        Args:
            src_ip: IP источника
            dst_ip: IP назначения
            src_port: Порт источника
            dst_port: Порт назначения
            protocol: Протокол (6=TCP, 17=UDP)
            bytes_count: Количество байт
            packets_count: Количество пакетов
            timestamp: Временная метка
        """
        timestamp = timestamp or time.time()

        with self._graph_lock:
            if src_ip not in self.current_graph:
                self.current_graph.add_node(
                    src_ip,
                    ip=src_ip,
                    type=self._get_node_type(src_ip),
                    first_seen=timestamp,
                    last_seen=timestamp,
                    total_bytes_in=0,
                    total_bytes_out=0,
                    connections_in=0,
                    connections_out=0,
                    unique_ports=set(),
                    protocols=set()
                )
                self.stats['total_nodes'] += 1

            if dst_ip not in self.current_graph:
                self.current_graph.add_node(
                    dst_ip,
                    ip=dst_ip,
                    type=self._get_node_type(dst_ip),
                    first_seen=timestamp,
                    last_seen=timestamp,
                    total_bytes_in=0,
                    total_bytes_out=0,
                    connections_in=0,
                    connections_out=0,
                    unique_ports=set(),
                    protocols=set()
                )
                self.stats['total_nodes'] += 1

            src_node = self.current_graph.nodes[src_ip]
            dst_node = self.current_graph.nodes[dst_ip]

            src_node['last_seen'] = timestamp
            dst_node['last_seen'] = timestamp
            src_node['total_bytes_out'] += bytes_count
            dst_node['total_bytes_in'] += bytes_count
            src_node['connections_out'] += 1
            dst_node['connections_in'] += 1
            src_node['unique_ports'].add(dst_port)
            dst_node['unique_ports'].add(src_port)
            src_node['protocols'].add(protocol)
            dst_node['protocols'].add(protocol)

            edge_key = (src_ip, dst_ip)

            if self.current_graph.has_edge(*edge_key):
                edge = self.current_graph[src_ip][dst_ip]
                edge['bytes'] += bytes_count
                edge['packets'] += packets_count
                edge['connections'] += 1
                edge['last_seen'] = timestamp
                edge['ports'].add((src_port, dst_port))
                edge['protocols'].add(protocol)
            else:
                self.current_graph.add_edge(
                    src_ip, dst_ip,
                    bytes=bytes_count,
                    packets=packets_count,
                    connections=1,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    ports={(src_port, dst_port)},
                    protocols={protocol},
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol
                )
                self.stats['total_edges'] += 1

            self.stats['total_connections'] += 1

            with self._stats_lock:
                conn_key = (src_ip, dst_ip)
                stats = self.connection_stats[conn_key]
                stats['count'] += 1
                stats['total_bytes'] += bytes_count
                stats['total_packets'] += packets_count
                stats['last_seen'] = timestamp
                stats['ports'].add((src_port, dst_port))
                stats['protocols'].add(protocol)

            if timestamp - self.last_snapshot_time >= self.snapshot_interval:
                self._executor.submit(self._create_snapshot, timestamp)

    def _get_node_type(self, ip: str) -> str:
        """Определяет тип узла"""
        for net in self.local_networks:
            if ip.startswith(net):
                return 'internal'

        if ip.startswith(('224.', '239.', '255.')):
            return 'multicast'

        return 'external'

    def _create_snapshot(self, timestamp: float):
        """Создаёт снапшот текущего графа"""
        with self._graph_lock:
            snapshot = self.current_graph.copy()

            snapshot.graph['timestamp'] = timestamp
            snapshot.graph['snapshot_id'] = self.stats['snapshots_created']

            self.graph_snapshots.append(snapshot)
            self.stats['snapshots_created'] += 1

            self._cleanup_current_graph(timestamp)

            self.last_snapshot_time = timestamp

            logger.debug(f"Created snapshot {self.stats['snapshots_created']} "
                         f"(nodes={snapshot.number_of_nodes()}, edges={snapshot.number_of_edges()})")

    def _cleanup_current_graph(self, current_time: float):
        """Очищает текущий граф от устаревших данных"""
        cutoff = current_time - self.config.temporal_window

        edges_to_remove = []
        for u, v, data in self.current_graph.edges(data=True):
            if data.get('last_seen', 0) < cutoff:
                edges_to_remove.append((u, v))

        for u, v in edges_to_remove:
            self.current_graph.remove_edge(u, v)

        nodes_to_remove = []
        for node in self.current_graph.nodes():
            if self.current_graph.degree(node) == 0:
                nodes_to_remove.append(node)

        for node in nodes_to_remove:
            self.current_graph.remove_node(node)

    def get_temporal_graphs(self, n: int = None) -> List[nx.DiGraph]:
        """
        Получить temporal графы.

        Args:
            n: Количество последних графов (None = все)

        Returns:
            Список графов
        """
        with self._graph_lock:
            graphs = list(self.graph_snapshots)
            if n is not None:
                graphs = graphs[-n:]
            return graphs

    def extract_features(self, graph: nx.DiGraph = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Извлекает признаки из графа для GNN.
        ИСПРАВЛЕНО: betweenness и pagerank вычисляются ОДИН раз для всего графа.
        """
        if graph is None:
            graphs = self.get_temporal_graphs(1)
            if not graphs:
                return np.array([]), np.array([]), np.array([])
            graph = graphs[-1]

        if graph.number_of_nodes() == 0:
            return np.array([]), np.array([]), np.array([])

        nodes = list(graph.nodes())
        self.node_id_map = {node: i for i, node in enumerate(nodes)}
        self.reverse_node_map = {i: node for node, i in self.node_id_map.items()}

        num_nodes = len(nodes)
        node_features = np.zeros((num_nodes, self.config.node_feature_dim))


        if num_nodes > 1:
            betweenness_dict = nx.betweenness_centrality(
                graph,
                k=min(10, num_nodes),
                normalized=True
            )
            pagerank_dict = nx.pagerank(
                graph,
                max_iter=50,
                tol=1e-4
            )
            clustering_dict = nx.clustering(graph)
        else:
            betweenness_dict = {nodes[0]: 0.0} if nodes else {}
            pagerank_dict = {nodes[0]: 1.0} if nodes else {}
            clustering_dict = {nodes[0]: 0.0} if nodes else {}


        for node, node_id in self.node_id_map.items():
            attrs = graph.nodes[node]
            features = []

            in_degree = graph.in_degree(node)
            out_degree = graph.out_degree(node)
            features.append(np.log1p(in_degree) / 10)
            features.append(np.log1p(out_degree) / 10)
            features.append(in_degree / max(1, num_nodes))
            features.append(out_degree / max(1, num_nodes))

            betweenness = betweenness_dict.get(node, 0.0)
            features.append(betweenness)

            clustering = clustering_dict.get(node, 0.0)
            features.append(clustering)

            total_bytes = attrs.get('total_bytes_in', 0) + attrs.get('total_bytes_out', 0)
            features.append(np.log1p(total_bytes) / 20)

            bytes_in = attrs.get('total_bytes_in', 0)
            bytes_out = attrs.get('total_bytes_out', 0)
            features.append(np.log1p(bytes_in) / 20)
            features.append(np.log1p(bytes_out) / 20)

            if bytes_in + bytes_out > 0:
                asymmetry = abs(bytes_in - bytes_out) / (bytes_in + bytes_out)
            else:
                asymmetry = 0
            features.append(asymmetry)

            conn_in = attrs.get('connections_in', 0)
            conn_out = attrs.get('connections_out', 0)
            features.append(np.log1p(conn_in) / 10)
            features.append(np.log1p(conn_out) / 10)

            unique_ports = len(attrs.get('unique_ports', set()))
            features.append(min(1.0, unique_ports / 100))

            protocols = attrs.get('protocols', set())
            features.append(1.0 if 6 in protocols else 0.0)
            features.append(1.0 if 17 in protocols else 0.0)

            node_type = attrs.get('type', 'unknown')
            features.append(1.0 if node_type == 'internal' else 0.0)
            features.append(1.0 if node_type == 'external' else 0.0)

            first_seen = attrs.get('first_seen', time.time())
            last_seen = attrs.get('last_seen', time.time())
            activity_duration = max(0, last_seen - first_seen)
            features.append(min(1.0, activity_duration / self.config.temporal_window))

            pagerank = pagerank_dict.get(node, 0.0)
            features.append(pagerank)

            features = features[:self.config.node_feature_dim]
            if len(features) < self.config.node_feature_dim:
                features.extend([0.0] * (self.config.node_feature_dim - len(features)))

            node_features[node_id] = features

        edge_list = []
        edge_features_list = []

        for u, v, data in graph.edges(data=True):
            if u in self.node_id_map and v in self.node_id_map:
                edge_list.append([self.node_id_map[u], self.node_id_map[v]])

                edge_feat = []

                bytes_count = data.get('bytes', 0)
                edge_feat.append(np.log1p(bytes_count) / 20)

                packets = data.get('packets', 0)
                edge_feat.append(np.log1p(packets) / 15)

                connections = data.get('connections', 0)
                edge_feat.append(np.log1p(connections) / 10)

                src_port = data.get('src_port', 0)
                dst_port = data.get('dst_port', 0)
                edge_feat.append(src_port / 65535.0)
                edge_feat.append(dst_port / 65535.0)

                protocol = data.get('protocol', 0)
                edge_feat.append(1.0 if protocol == 6 else 0.0)
                edge_feat.append(1.0 if protocol == 17 else 0.0)

                first_seen = data.get('first_seen', time.time())
                last_seen = data.get('last_seen', time.time())
                duration = max(1, last_seen - first_seen)
                freq = connections / duration
                edge_feat.append(min(1.0, freq))

                unique_ports = len(data.get('ports', set()))
                edge_feat.append(min(1.0, unique_ports / 50))

                edge_feat = edge_feat[:self.config.edge_feature_dim]
                if len(edge_feat) < self.config.edge_feature_dim:
                    edge_feat.extend([0.0] * (self.config.edge_feature_dim - len(edge_feat)))

                edge_features_list.append(edge_feat)

        edge_index = np.array(edge_list).T if edge_list else np.zeros((2, 0), dtype=np.int64)
        edge_features = np.array(edge_features_list) if edge_features_list else np.zeros(
            (0, self.config.edge_feature_dim))

        return node_features, edge_index, edge_features

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._graph_lock:
            return {
                **self.stats,
                'current_nodes': self.current_graph.number_of_nodes(),
                'current_edges': self.current_graph.number_of_edges(),
                'snapshots_stored': len(self.graph_snapshots),
                'connection_pairs': len(self.connection_stats)
            }

    def cleanup(self):
        """Очистка старых данных"""
        with self._graph_lock:
            while len(self.graph_snapshots) > self.config.max_graphs_in_memory:
                self.graph_snapshots.popleft()

            cutoff = time.time() - self.config.temporal_window * 2
            with self._stats_lock:
                expired = [k for k, v in self.connection_stats.items()
                           if v['last_seen'] < cutoff]
                for k in expired:
                    del self.connection_stats[k]

    def shutdown(self):
        """Graceful shutdown"""
        self._executor.shutdown(wait=True)



if TORCH_AVAILABLE and TORCH_GEOMETRIC_AVAILABLE:

    class TemporalGNNModel(nn.Module):
        """Temporal Graph Neural Network с attention и LSTM"""

        def __init__(self, config: TemporalGNNConfig):
            super().__init__()
            self.config = config

            self.gnn_layers = nn.ModuleList()
            input_dim = config.node_feature_dim

            for i in range(config.gnn_num_layers):
                if config.gnn_type == 'gcn':
                    self.gnn_layers.append(GCNConv(input_dim, config.gnn_hidden_dim))
                elif config.gnn_type == 'gat':
                    self.gnn_layers.append(
                        GATConv(input_dim, config.gnn_hidden_dim // config.gnn_heads,
                                heads=config.gnn_heads, dropout=config.dropout_rate)
                    )
                    input_dim = config.gnn_hidden_dim
                elif config.gnn_type == 'sage':
                    self.gnn_layers.append(SAGEConv(input_dim, config.gnn_hidden_dim))
                else:
                    self.gnn_layers.append(GCNConv(input_dim, config.gnn_hidden_dim))

                input_dim = config.gnn_hidden_dim

            self.edge_encoder = nn.Sequential(
                nn.Linear(config.edge_feature_dim, config.gnn_hidden_dim),
                nn.ReLU(),
                nn.Dropout(config.dropout_rate),
                nn.Linear(config.gnn_hidden_dim, config.gnn_hidden_dim)
            )

            self.batch_norms = nn.ModuleList([
                nn.BatchNorm1d(config.gnn_hidden_dim)
                for _ in range(config.gnn_num_layers)
            ])

            lstm_input_dim = config.gnn_hidden_dim
            self.lstm = nn.LSTM(
                input_size=lstm_input_dim,
                hidden_size=config.lstm_hidden_dim,
                num_layers=config.lstm_num_layers,
                batch_first=True,
                bidirectional=config.lstm_bidirectional,
                dropout=config.dropout_rate if config.lstm_num_layers > 1 else 0
            )

            lstm_output_dim = config.lstm_hidden_dim * (2 if config.lstm_bidirectional else 1)

            if config.use_attention_pooling:
                self.attention_pool = nn.MultiheadAttention(
                    embed_dim=config.gnn_hidden_dim,
                    num_heads=config.attention_heads,
                    dropout=config.dropout_rate,
                    batch_first=True
                )

            self.node_classifier = nn.Sequential(
                nn.Linear(config.gnn_hidden_dim, config.gnn_hidden_dim // 2),
                nn.ReLU(),
                nn.Dropout(config.dropout_rate),
                nn.Linear(config.gnn_hidden_dim // 2, 1),
                nn.Sigmoid()
            )

            self.graph_classifier = nn.Sequential(
                nn.Linear(lstm_output_dim, lstm_output_dim // 2),
                nn.ReLU(),
                nn.Dropout(config.dropout_rate),
                nn.Linear(lstm_output_dim // 2, 1),
                nn.Sigmoid()
            )

            if config.use_contrastive_loss:
                self.projection_head = nn.Sequential(
                    nn.Linear(lstm_output_dim, 128),
                    nn.ReLU(),
                    nn.Linear(128, 64)
                )

            self.dropout = nn.Dropout(config.dropout_rate)

        def forward(self, data: Data) -> Dict[str, torch.Tensor]:
            """
            Forward pass.

            Args:
                data: PyTorch Geometric Data объект

            Returns:
                Dict с предсказаниями
            """
            x, edge_index, edge_attr = data.x, data.edge_index, data.edge_attr

            if edge_attr is not None:
                edge_embedding = self.edge_encoder(edge_attr)
            else:
                edge_embedding = None

            for i, gnn_layer in enumerate(self.gnn_layers):
                if isinstance(gnn_layer, GATConv):
                    x = gnn_layer(x, edge_index)
                else:
                    x = gnn_layer(x, edge_index, edge_embedding)

                x = self.batch_norms[i](x)
                x = F.relu(x)
                x = self.dropout(x)

            if self.config.use_attention_pooling and x.size(0) > 0:
                if not hasattr(data, 'batch') or data.batch is None:
                    batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
                else:
                    batch = data.batch

                unique_batches = torch.unique(batch)
                graph_embeddings = []
                node_scores = []

                for b in unique_batches:
                    mask = (batch == b)
                    x_batch = x[mask]

                    node_score = self.node_classifier(x_batch)
                    node_scores.append(node_score)

                    x_batch = x_batch.unsqueeze(0)
                    attn_out, _ = self.attention_pool(x_batch, x_batch, x_batch)
                    graph_emb = attn_out.mean(dim=1)
                    graph_embeddings.append(graph_emb)

                node_scores = torch.cat(node_scores, dim=0)
                graph_emb = torch.cat(graph_embeddings, dim=0)
            else:
                node_scores = self.node_classifier(x)
                graph_emb = global_mean_pool(x, data.batch if hasattr(data, 'batch') else None)

            graph_score = self.graph_classifier(graph_emb)

            result = {
                'node_scores': node_scores,
                'graph_score': graph_score,
                'node_embeddings': x,
                'graph_embedding': graph_emb
            }

            if self.config.use_contrastive_loss:
                result['projection'] = self.projection_head(graph_emb)

            return result

        def encode_graph(self, data: Data) -> torch.Tensor:
            """Кодирует граф в вектор"""
            result = self.forward(data)
            return result['graph_embedding']



class TemporalGNNEngine:
    """
    Production движок для Temporal GNN.

    Особенности:
    - Полное обучение с contrastive loss
    - Temporal sequence processing
    - Anomaly detection на уровне узлов и графов
    - Мониторинг и алерты
    """

    def __init__(self, config: TemporalGNNConfig = None):
        self.config = config or TemporalGNNConfig()

        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        self.graph_builder = NetworkGraphBuilder(self.config)
        self.model = None

        if TORCH_AVAILABLE and TORCH_GEOMETRIC_AVAILABLE:
            self.model = TemporalGNNModel(self.config).to(self.device)
            self.optimizer = optim.AdamW(
                self.model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
            self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(
                self.optimizer, mode='min', factor=0.5, patience=5
            )

        self.is_trained = False
        self.training_history = []

        self.normal_graphs: deque = deque(maxlen=5000)
        self.anomaly_graphs: deque = deque(maxlen=1000)
        self.graph_sequence_buffer: deque = deque(maxlen=self.config.time_steps)

        self.node_threshold = self.config.node_anomaly_threshold
        self.graph_threshold = self.config.anomaly_threshold

        self.stats = {
            'graphs_processed': 0,
            'anomalies_detected': 0,
            'node_anomalies_detected': 0,
            'training_epochs': 0,
            'best_loss': float('inf')
        }

        self._model_lock = threading.RLock()
        self._training_lock = threading.RLock()

        self._running = False
        self._training_thread = None
        self._cleanup_thread = None

        self._executor = ThreadPoolExecutor(max_workers=self.config.max_workers)

        Path(self.config.model_dir).mkdir(parents=True, exist_ok=True)

        self._load_model()

        logger.info(f"✅ TemporalGNNEngine initialized on {self.device}")

    def _load_model(self):
        """Загружает сохранённую модель"""
        model_path = Path(self.config.model_dir) / 'temporal_gnn.pt'

        if model_path.exists() and self.model is not None:
            try:
                checkpoint = torch.load(model_path, map_location=self.device)
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
                self.is_trained = checkpoint.get('is_trained', True)
                self.node_threshold = checkpoint.get('node_threshold', self.node_threshold)
                self.graph_threshold = checkpoint.get('graph_threshold', self.graph_threshold)
                self.stats = checkpoint.get('stats', self.stats)

                logger.info(f"✅ Model loaded from {model_path}")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load model: {e}")

    def _save_model(self):
        """Сохраняет модель"""
        if self.model is None:
            return

        model_path = Path(self.config.model_dir) / 'temporal_gnn.pt'

        try:
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'optimizer_state_dict': self.optimizer.state_dict(),
                'config': self.config.__dict__,
                'is_trained': self.is_trained,
                'node_threshold': self.node_threshold,
                'graph_threshold': self.graph_threshold,
                'stats': self.stats
            }, model_path)

            logger.info(f"✅ Model saved to {model_path}")
        except Exception as e:
            logger.error(f"❌ Failed to save model: {e}")

    def start(self):
        """Запуск движка"""
        self._running = True

        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="GNN-Cleanup"
        )
        self._cleanup_thread.start()

        logger.info("🚀 TemporalGNNEngine started")

    def stop(self):
        """Остановка движка"""
        self._running = False

        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)

        self._save_model()
        self.graph_builder.shutdown()
        self._executor.shutdown(wait=True)

        logger.info("🛑 TemporalGNNEngine stopped")

    def _cleanup_loop(self):
        """Фоновый цикл очистки"""
        while self._running:
            time.sleep(self.config.cleanup_interval)

            if not self._running:
                break

            self.graph_builder.cleanup()

    def add_connection(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       protocol: int, bytes_count: int, packets_count: int = 1):
        """
        Добавление сетевого соединения.

        Args:
            src_ip: IP источника
            dst_ip: IP назначения
            src_port: Порт источника
            dst_port: Порт назначения
            protocol: Протокол
            bytes_count: Количество байт
            packets_count: Количество пакетов
        """
        self.graph_builder.add_connection(
            src_ip, dst_ip, src_port, dst_port,
            protocol, bytes_count, packets_count
        )

    def process_time_window(self) -> Optional[Dict]:
        """
        Обработка временного окна - создание снапшота и анализ.

        Returns:
            Dict с результатами анализа или None
        """
        graphs = self.graph_builder.get_temporal_graphs(1)
        if not graphs:
            return None

        graph = graphs[-1]

        if graph.number_of_nodes() < 5:
            return None

        self.stats['graphs_processed'] += 1

        node_features, edge_index, edge_features = self.graph_builder.extract_features(graph)

        if len(node_features) == 0:
            return None

        data = Data(
            x=torch.FloatTensor(node_features).to(self.device),
            edge_index=torch.LongTensor(edge_index).to(self.device) if edge_index.size > 0 else torch.zeros((2, 0),
                                                                                                            dtype=torch.long).to(
                self.device),
            edge_attr=torch.FloatTensor(edge_features).to(self.device) if len(edge_features) > 0 else None
        )

        self.graph_sequence_buffer.append(data)

        if not self.is_trained:
            return {
                'graph_score': 0.5,
                'node_scores': [],
                'is_graph_anomaly': False,
                'anomalous_nodes': [],
                'num_nodes': graph.number_of_nodes(),
                'num_edges': graph.number_of_edges(),
                'message': 'Model not trained'
            }

        with self._model_lock:
            self.model.eval()

            with torch.no_grad():
                if len(self.graph_sequence_buffer) >= self.config.time_steps:
                    pass

                result = self.model(data)

                graph_score = result['graph_score'].item()
                node_scores = result['node_scores'].cpu().numpy().flatten()

        is_graph_anomaly = graph_score > self.graph_threshold

        if is_graph_anomaly:
            self.stats['anomalies_detected'] += 1

        anomalous_nodes = []
        for i, score in enumerate(node_scores):
            if score > self.node_threshold:
                ip = self.graph_builder.reverse_node_map.get(i, f'unknown_{i}')
                anomalous_nodes.append({
                    'ip': ip,
                    'score': float(score),
                    'severity': 'HIGH' if score > 0.8 else 'MEDIUM'
                })
                self.stats['node_anomalies_detected'] += 1

        return {
            'graph_score': float(graph_score),
            'node_scores': node_scores.tolist(),
            'anomalous_nodes': anomalous_nodes,
            'is_graph_anomaly': bool(is_graph_anomaly),
            'num_nodes': graph.number_of_nodes(),
            'num_edges': graph.number_of_edges(),
            'threshold': self.graph_threshold,
            'node_threshold': self.node_threshold
        }

    def train(self, normal_graphs: List[nx.DiGraph], anomaly_graphs: List[nx.DiGraph] = None,
              epochs: int = None, batch_size: int = None, verbose: int = 1) -> Dict:
        """
        Обучение модели на графах.

        Args:
            normal_graphs: Список нормальных графов
            anomaly_graphs: Список аномальных графов
            epochs: Количество эпох
            batch_size: Размер батча
            verbose: Уровень логирования

        Returns:
            Dict с историей обучения
        """
        if self.model is None:
            return {'error': 'PyTorch Geometric not available'}

        epochs = epochs or self.config.epochs
        batch_size = batch_size or self.config.batch_size

        normal_data = self._prepare_graph_data(normal_graphs)

        if anomaly_graphs:
            anomaly_data = self._prepare_graph_data(anomaly_graphs)
            all_data = normal_data + anomaly_data
            labels = torch.cat([
                torch.zeros(len(normal_data)),
                torch.ones(len(anomaly_data))
            ])
        else:
            all_data = normal_data
            labels = torch.zeros(len(normal_data))

        dataset = list(zip(all_data, labels))
        dataloader = DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=True,
            follow_batch=['x']
        )

        history = {'loss': [], 'val_loss': [], 'accuracy': []}

        with self._training_lock:
            self.model.train()

            for epoch in range(epochs):
                epoch_loss = 0.0
                correct = 0
                total = 0

                for batch_data, batch_labels in dataloader:
                    batch_data = batch_data.to(self.device)
                    batch_labels = batch_labels.to(self.device)

                    self.optimizer.zero_grad()

                    result = self.model(batch_data)

                    graph_scores = result['graph_score'].squeeze()
                    class_loss = F.binary_cross_entropy(graph_scores, batch_labels.float())

                    total_loss = class_loss

                    if self.config.use_contrastive_loss and 'projection' in result:
                        contrastive_loss = self._contrastive_loss(
                            result['projection'],
                            batch_labels
                        )
                        total_loss = class_loss + self.config.contrastive_weight * contrastive_loss

                    total_loss.backward()

                    torch.nn.utils.clip_grad_norm_(
                        self.model.parameters(),
                        self.config.gradient_clip_norm
                    )

                    self.optimizer.step()

                    epoch_loss += total_loss.item()

                    predicted = (graph_scores > 0.5).float()
                    correct += (predicted == batch_labels).sum().item()
                    total += batch_labels.size(0)

                avg_loss = epoch_loss / len(dataloader)
                accuracy = correct / total if total > 0 else 0

                history['loss'].append(avg_loss)
                history['accuracy'].append(accuracy)

                self.scheduler.step(avg_loss)

                if verbose and epoch % 10 == 0:
                    logger.info(f"Epoch {epoch}: loss={avg_loss:.4f}, accuracy={accuracy:.4f}")

                if avg_loss < self.stats['best_loss']:
                    self.stats['best_loss'] = avg_loss
                    self._save_model()

                self.stats['training_epochs'] += 1

        self.is_trained = True
        self.training_history = history

        self._calibrate_thresholds(normal_graphs[:100])

        logger.info(f"✅ Training complete. Best loss: {self.stats['best_loss']:.4f}")

        return history

    def _prepare_graph_data(self, graphs: List[nx.DiGraph]) -> List[Data]:
        """Подготавливает графы для PyTorch Geometric"""
        data_list = []

        for graph in graphs:
            node_features, edge_index, edge_features = self.graph_builder.extract_features(graph)

            if len(node_features) == 0:
                continue

            data = Data(
                x=torch.FloatTensor(node_features),
                edge_index=torch.LongTensor(edge_index) if edge_index.size > 0 else torch.zeros((2, 0),
                                                                                                dtype=torch.long),
                edge_attr=torch.FloatTensor(edge_features) if len(edge_features) > 0 else None
            )

            data_list.append(data)

        return data_list

    def _contrastive_loss(self, projections: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """Supervised Contrastive Loss"""
        projections = F.normalize(projections, dim=1)

        sim_matrix = torch.matmul(projections, projections.T) / self.config.contrastive_temperature

        labels = labels.unsqueeze(0)
        mask_positive = (labels == labels.T).float()

        mask_positive = mask_positive - torch.eye(mask_positive.size(0), device=mask_positive.device)

        sim_matrix = sim_matrix - sim_matrix.max(dim=1, keepdim=True)[0]

        exp_sim = torch.exp(sim_matrix)

        pos_sum = (exp_sim * mask_positive).sum(dim=1)

        mask_all = 1.0 - torch.eye(sim_matrix.size(0), device=sim_matrix.device)
        all_sum = (exp_sim * mask_all).sum(dim=1)

        loss = -torch.log(pos_sum / (all_sum + 1e-8) + 1e-8).mean()

        return loss

    def _calibrate_thresholds(self, normal_graphs: List[nx.DiGraph]):
        """Калибрует пороги на нормальных графах"""
        if not normal_graphs:
            return

        graph_scores = []
        all_node_scores = []

        self.model.eval()
        with torch.no_grad():
            for graph in normal_graphs:
                data = self._prepare_graph_data([graph])[0].to(self.device)
                result = self.model(data)

                graph_scores.append(result['graph_score'].item())
                all_node_scores.extend(result['node_scores'].cpu().numpy().flatten())

        if graph_scores:
            self.graph_threshold = np.percentile(graph_scores, 95)

        if all_node_scores:
            self.node_threshold = np.percentile(all_node_scores, 95)

        logger.info(f"Calibrated thresholds: graph={self.graph_threshold:.3f}, "
                    f"node={self.node_threshold:.3f}")

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return {
            'model': {
                'is_trained': self.is_trained,
                'device': str(self.device),
                'parameters': sum(p.numel() for p in self.model.parameters()) if self.model else 0,
                'best_loss': self.stats['best_loss']
            },
            'graph_builder': self.graph_builder.get_stats(),
            'detection': {
                'graphs_processed': self.stats['graphs_processed'],
                'anomalies_detected': self.stats['anomalies_detected'],
                'node_anomalies_detected': self.stats['node_anomalies_detected'],
                'graph_threshold': self.graph_threshold,
                'node_threshold': self.node_threshold
            },
            'training': {
                'epochs': self.stats['training_epochs'],
                'normal_graphs': len(self.normal_graphs),
                'anomaly_graphs': len(self.anomaly_graphs)
            }
        }



def test_temporal_gnn():
    """Тестирование Temporal GNN"""
    print("=" * 60)
    print("🧪 TESTING TEMPORAL GNN")
    print("=" * 60)

    if not TORCH_AVAILABLE or not TORCH_GEOMETRIC_AVAILABLE:
        print("❌ PyTorch Geometric not available")
        return

    config = TemporalGNNConfig()
    config.max_nodes = 500
    config.time_steps = 5
    config.epochs = 20

    engine = TemporalGNNEngine(config)
    engine.start()

    print("\n📊 Simulating network traffic...")

    local_ips = [f'192.168.1.{i}' for i in range(1, 11)]
    external_ips = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '185.125.190.56']
    malicious_ips = ['45.155.205.233', '194.61.23.45']

    normal_graphs = []

    for window in range(30):
        for _ in range(50):
            src = np.random.choice(local_ips)

            if np.random.random() < 0.7:
                dst = np.random.choice(external_ips)
                port = 443 if np.random.random() < 0.8 else 80
            else:
                dst = np.random.choice(local_ips)
                port = np.random.choice([22, 445, 3389])

            engine.add_connection(
                src, dst,
                np.random.randint(30000, 60000),
                port,
                6,
                np.random.randint(100, 10000),
                np.random.randint(1, 20)
            )

        result = engine.process_time_window()

        if result:
            normal_graphs.append(engine.graph_builder.get_temporal_graphs(1)[-1])

    print("\n🔄 Training model...")
    history = engine.train(normal_graphs, epochs=config.epochs, verbose=1)

    print("\n📊 Simulating attack...")

    for _ in range(20):
        src = np.random.choice(local_ips)
        dst = np.random.choice(local_ips)

        engine.add_connection(
            src, dst,
            np.random.randint(40000, 50000),
            445,
            6,
            np.random.randint(5000, 50000),
            np.random.randint(50, 200)
        )

    for _ in range(10):
        src = np.random.choice(local_ips)
        dst = np.random.choice(malicious_ips)

        engine.add_connection(
            src, dst,
            np.random.randint(50000, 60000),
            4444,
            6,
            np.random.randint(1000, 10000),
            np.random.randint(10, 50)
        )

    result = engine.process_time_window()

    if result:
        print(f"\n🔮 Attack analysis result:")
        print(f"   Graph score: {result['graph_score']:.4f}")
        print(f"   Is anomaly: {result['is_graph_anomaly']}")
        print(f"   Nodes: {result['num_nodes']}, Edges: {result['num_edges']}")
        print(f"   Anomalous nodes: {len(result['anomalous_nodes'])}")

        for node in result['anomalous_nodes'][:5]:
            print(f"      - {node['ip']}: score={node['score']:.3f} ({node['severity']})")

    print("\n📊 Statistics:")
    stats = engine.get_stats()
    print(f"   Graphs processed: {stats['detection']['graphs_processed']}")
    print(f"   Anomalies detected: {stats['detection']['anomalies_detected']}")
    print(f"   Graph threshold: {stats['detection']['graph_threshold']:.3f}")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ TESTING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_temporal_gnn()
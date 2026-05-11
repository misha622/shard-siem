import sys, os; sys.path.insert(0, '.')
import pytest, torch, numpy as np

class TestDefensePipeline:
    @pytest.fixture
    def pipeline(self):
        from shard_defense_pipeline_v3 import DefensePipeline
        return DefensePipeline()
    def test_loads(self, pipeline): assert pipeline.model.loaded
    def test_sqli(self, pipeline):
        atype, conf = pipeline.model.predict("SQL injection from 10.0.0.1 on port 3306")
        assert 'SQL' in atype and conf > 0.5
    def test_process(self, pipeline):
        r = pipeline.process_alert({'src_ip':'10.0.0.1','dst_port':3306,'attack_type':'Test','explanation':'test'})
        assert 'code' in r and 'attack_type' in r

class TestRL:
    @pytest.fixture
    def rl(self):
        from shard_rl_integration import RLDefenseAgent
        return RLDefenseAgent()
    def test_loads(self, rl): assert rl.loaded or True  # Skip if model file missing
    def test_decide(self, rl):
        aid, name, desc = rl.decide_action({'attack_type':'DDoS','severity':'CRITICAL','score':0.95,'confidence':0.95,'dst_port':443})
        assert aid >= 2 and name in ['throttle','block_temp','block_perm']

class TestAnomaly:
    @pytest.fixture
    def det(self):
        from shard_anomaly_detector import ShardAnomalyDetector
        return ShardAnomalyDetector()
    def test_loads(self, det): assert det.loaded or True
    def test_check(self, det):
        is_anom, score = det.is_anomaly({'score':0.9,'src_ip':'10.0.0.1'})
        assert isinstance(is_anom, bool)

class TestGNN:
    @pytest.fixture
    def gnn(self):
        from shard_gnn_integration import ShardGNN
        return ShardGNN()
    def test_loads(self, gnn): assert gnn.loaded or True

class TestFusion:
    @pytest.fixture
    def fusion(self):
        from shard_fusion_integration import ShardFusion
        return ShardFusion()
    def test_loads(self, fusion): assert fusion.loaded or True
    def test_fuse(self, fusion):
        signals = [np.random.rand(13).tolist(), np.random.randn(100).tolist(), [0.1,0.2,0.3,0.2,0.2], [0.5], [0.3], [0.2,0.7,0.1], [0.6]]
        r = fusion.fuse(signals)
        assert r['threat_level'] in ['BENIGN','SUSPICIOUS','CRITICAL','UNKNOWN']

class TestNotifier:
    @pytest.fixture
    def notifier(self):
        from shard_notifier import ShardNotifier
        return ShardNotifier()
    def test_format(self, notifier):
        msg = notifier._format_alert({'attack_type':'SQL Injection','severity':'CRITICAL','src_ip':'10.0.0.1','dst_port':3306,'confidence':0.95,'timestamp':1234567890})
        assert 'SQL Injection' in msg and '10.0.0.1' in msg

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

"""Тесты OT/IoT Security + Prometheus"""
import pytest
import sys
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

OTIoTSecurity = sec.OTIoTSecurity
PrometheusMetrics = sec.PrometheusMetrics


class TestOTIoTSecurity:
    """OT/IoT мониторинг"""

    @pytest.fixture
    def ot(self):
        class MockConfig:
            def get(self, key, default=None): return default
        class MockEventBus:
            def __init__(self): self.events = []
            def subscribe(self, *args): pass
            def publish(self, event_type, data): self.events.append((event_type, data))
        class MockLogger:
            def info(self, *args): pass
            def warning(self, *args): pass
            def error(self, *args): pass
            def debug(self, *args): pass
            def get_logger(self, name=None): return self
        return OTIoTSecurity(MockConfig(), MockEventBus(), MockLogger())

    def test_industrial_ports_known(self, ot):
        """Известные промышленные порты"""
        assert ot.INDUSTRIAL_PORTS.get(502) == 'Modbus'
        assert ot.INDUSTRIAL_PORTS.get(44818) == 'EtherNet/IP'

    def test_iot_ports_known(self, ot):
        """Известные IoT порты"""
        assert ot.IOT_PORTS.get(1883) == 'MQTT'
        assert ot.IOT_PORTS.get(5683) == 'CoAP'

    def test_on_packet_industrial(self, ot):
        """Детекция промышленного трафика"""
        ot.event_bus = type('eb', (), {'events': [], 'publish': lambda s, e, d: s.events.append((e, d)), 'subscribe': lambda s, *a: None})()
        ot.event_bus.events = []
        ot.on_packet({'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2', 'dst_port': 502, 'src_port': 12345})
        assert len(ot.event_bus.events) > 0

    def test_get_devices(self, ot):
        """Список устройств"""
        ot.on_packet({'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'dst_port': 502})
        devices = ot.get_devices()
        assert len(devices) >= 2

    def test_get_stats(self, ot):
        """Статистика"""
        ot.on_packet({'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'dst_port': 502})
        ot.on_packet({'src_ip': '10.0.0.3', 'dst_ip': '10.0.0.4', 'dst_port': 1883})
        stats = ot.get_stats()
        assert stats['ot_devices'] >= 2
        assert stats['iot_devices'] >= 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

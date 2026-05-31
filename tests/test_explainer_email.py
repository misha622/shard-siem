"""Тесты AlertExplainer + EmailThreatAnalyzer"""
import pytest
import sys
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

AlertExplainer = sec.AlertExplainer
EmailThreatAnalyzer = sec.EmailThreatAnalyzer


class TestAlertExplainer:
    """Объяснение алертов"""

    @pytest.fixture
    def explainer(self):
        return AlertExplainer()

    def test_explain_brute_force(self, explainer):
        """Объяснение Brute Force"""
        alert = {'attack_type': 'Brute Force', 'score': 0.8, 'src_ip': '10.0.0.1'}
        explanation = explainer.explain(alert)
        assert 'Brute Force' in explanation
        assert 'MITRE' in explanation

    def test_explain_data_exfiltration(self, explainer):
        """Объяснение утечки данных"""
        alert = {'attack_type': 'Data Exfiltration', 'score': 0.95, 'src_ip': '10.0.0.1', 'total_bytes_recent': 100_000_000}
        explanation = explainer.explain(alert)
        assert 'Exfiltration' in explanation

    def test_recommendation_critical(self, explainer):
        """Рекомендация для критического алерта"""
        alert = {'attack_type': 'DDoS', 'score': 0.9, 'src_ip': '10.0.0.1'}
        explanation = explainer.explain(alert)
        assert 'КРИТИЧЕСКИЙ' in explanation

    def test_mitre_techniques(self, explainer):
        """MITRE ATT&CK маппинг"""
        assert explainer.mitre_techniques.get('Brute Force') == 'T1110'
        assert explainer.mitre_techniques.get('Phishing') == 'T1566'


class TestEmailThreatAnalyzer:
    """Анализ email угроз"""

    @pytest.fixture
    def analyzer(self):
        class MockConfig:
            def get(self, key, default=None): return default
        class MockEventBus:
            def subscribe(self, *args): pass
        class MockLogger:
            def info(self, *args): pass
            def warning(self, *args): pass
            def error(self, *args): pass
            def debug(self, *args): pass
            def get_logger(self, name=None): return self
        return EmailThreatAnalyzer(MockConfig(), MockEventBus(), MockLogger())

    def test_analyze_phishing(self, analyzer):
        """Детекция фишинга"""
        result = analyzer.analyze_email(
            sender='bad@evil.com',
            subject='Verify your account urgently',
            body='Click here to verify your account immediately',
            attachments=[]
        )
        assert result['is_suspicious'] is True
        assert result['score'] > 0.2

    def test_analyze_clean_email(self, analyzer):
        """Чистое письмо"""
        result = analyzer.analyze_email(
            sender='friend@example.com',
            subject='Hello',
            body='How are you?',
            attachments=[]
        )
        assert result['score'] < 0.3

    def test_dangerous_attachment(self, analyzer):
        """Опасное вложение"""
        result = analyzer.analyze_email(
            sender='bad@evil.com',
            subject='Invoice',
            body='Please see attached',
            attachments=['invoice.exe']
        )
        assert result['is_suspicious'] is True

    def test_extract_urls(self, analyzer):
        """Извлечение URL"""
        urls = analyzer._extract_urls('Visit https://evil.com and http://bad.org')
        assert len(urls) == 2

    def test_suspicious_url_detection(self, analyzer):
        """Подозрительные URL"""
        assert analyzer._is_suspicious_url('https://bit.ly/abc') is True
        assert analyzer._is_suspicious_url('https://192.168.1.1/login') is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

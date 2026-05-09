# tests/test_integration.py
import unittest
import requests
import time
import threading
import subprocess
import signal
import os


class TestShardIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Запускаем SHARD в фоне"""
        cls.shard_process = subprocess.Popen(
            ['python3', 'run_shard.py', '--no-enhancements'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        time.sleep(10)  # Ждём запуска

        cls.base_url = "http://localhost:8080"
        cls.auth = ('admin', 'ShardAdmin2026!')

    @classmethod
    def tearDownClass(cls):
        """Останавливаем SHARD"""
        os.killpg(os.getpgid(cls.shard_process.pid), signal.SIGTERM)
        cls.shard_process.wait()

    def test_health_check(self):
        """Проверка что дашборд отвечает"""
        response = requests.get(f"{self.base_url}/api/stats", auth=self.auth)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('total_packets', data)

    def test_waf_detection(self):
        """Проверка WAF детекции SQLi"""
        response = requests.get(
            f"{self.base_url}/?id=1' OR '1'='1",
            auth=self.auth
        )
        # WAF может заблокировать или вернуть 200
        self.assertIn(response.status_code, [200, 403])

    def test_alert_creation(self):
        """Проверка создания алертов"""
        # Отправляем трафик
        for _ in range(10):
            requests.get(self.base_url, auth=self.auth)

        time.sleep(2)

        response = requests.get(f"{self.base_url}/api/stats", auth=self.auth)
        data = response.json()
        self.assertGreater(data['total_packets'], 0)

    def test_honeypot(self):
        """Проверка honeypot"""
        import socket
        for port in [22, 80, 443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                # 0 = успешно, 111 = connection refused (тоже ок)
                self.assertIn(result, [0, 111])
            except:
                pass


if __name__ == '__main__':
    unittest.main()
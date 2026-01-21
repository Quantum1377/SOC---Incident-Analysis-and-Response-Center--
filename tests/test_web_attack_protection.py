import unittest
from unittest.mock import patch, mock_open, MagicMock
import time
import os
import shutil

# Importando o handler e a fábrica de firewall
from modulos_de_defesa.web_attack_protection.monitor_v2 import WebAttackLogHandler, WEB_ATTACK_PATTERNS
from modulos_de_defesa.firewall import MockFirewall

class TestWebAttackProtection(unittest.TestCase):

    def setUp(self):
        """Configura um ambiente de teste limpo antes de cada teste."""
        self.test_dir = "./test_logs_webattack"
        os.makedirs(self.test_dir, exist_ok=True)
        self.log_file_path = os.path.join(self.test_dir, "access.log")

        # Garante que o arquivo de log esteja vazio para cada teste
        with open(self.log_file_path, "w") as f:
            f.write("")

        self.mock_firewall = MockFirewall()
        self.mock_event_client = MagicMock()
        self.config = {
            'log_file': self.log_file_path,
            'block_duration': 5, # segundos
            'firewall_type': 'mock'
        }
        # Instancia o handler para o teste
        self.handler = WebAttackLogHandler(self.config, self.mock_firewall, self.log_file_path, self.mock_event_client)
        
        # Mock de time.time para controlar o tempo nos testes
        self.mock_time = 0
        self.patcher_time = patch('time.time', side_effect=lambda: self.mock_time)
        self.mock_get_time = self.patcher_time.start()

    def tearDown(self):
        """Limpa o ambiente de teste após cada teste."""
        if self.handler.file:
            self.handler.file.close() # Fechar o arquivo de log
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        self.patcher_time.stop()

    def _write_log_entry(self, ip_address, request_path, status="200", user_agent="Mozilla/5.0"):
        """Escreve uma entrada de log de acesso web formatada."""
        log_entry = (
            f"{ip_address} - - [{time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime(self.mock_time))}] "
            f'"GET {request_path} HTTP/1.1" {status} 1234 "-" "{user_agent}"'
        )
        with open(self.log_file_path, "a") as f:
            f.write(log_entry + "\n")
        self.handler.check_new_lines() # Processa a nova linha imediatamente

    def test_sql_injection_detection_and_blocking(self):
        test_ip = "192.168.1.10"
        malicious_request = "/index.php?id=1%27+UNION+SELECT+1,2,3-- "
        
        self.mock_time = 1
        self._write_log_entry(test_ip, malicious_request)

        self.assertIn(test_ip, self.mock_firewall.blocked_ips)

    def test_path_traversal_detection_and_blocking(self):
        """Testa a detecção de Path Traversal e o bloqueio de IP."""
        test_ip = "192.168.1.11"
        malicious_request = "/etc/passwd../../../" # Path Traversal
        
        self.mock_time = 2
        self._write_log_entry(test_ip, malicious_request)

        self.assertIn(test_ip, self.mock_firewall.blocked_ips)

    def test_command_injection_detection_and_blocking(self):
        """Testa a detecção de Command Injection e o bloqueio de IP."""
        test_ip = "192.168.1.12"
        malicious_request = "/?cmd=test;ls" # Command Injection
        
        self.mock_time = 3
        self._write_log_entry(test_ip, malicious_request)

        self.assertIn(test_ip, self.mock_firewall.blocked_ips)

    def test_xss_detection_and_blocking(self):
        """Testa a detecção de XSS e o bloqueio de IP."""
        test_ip = "192.168.1.13"
        malicious_request = "/?q=<script>alert(1)</script>" # XSS
        
        self.mock_time = 4
        self._write_log_entry(test_ip, malicious_request)

        self.assertIn(test_ip, self.mock_firewall.blocked_ips)

    def test_ip_unblocking_after_duration(self):
        """Testa se um IP é desbloqueado automaticamente após a duração configurada."""
        test_ip = "192.168.1.14"
        malicious_request = "/index.php?id=1%27+UNION+SELECT+1,2,3-- "
        
        # Bloqueia o IP
        self.mock_time = 10
        self._write_log_entry(test_ip, malicious_request)

        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Deve estar bloqueado

        # Avança o tempo para antes do desbloqueio
        self.mock_time = 10 + self.config['block_duration'] - 1
        self.handler.cleanup_blocked_ips()

        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Ainda deve estar bloqueado

        # Avança o tempo para após o desbloqueio
        self.mock_time = 10 + self.config['block_duration'] + 1
        self.handler.cleanup_blocked_ips()

        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Deve ter sido desbloqueado
        self.assertIn(test_ip, self.mock_firewall.unblocked_ips) # Deve estar na lista de desbloqueados do mock

    def test_normal_traffic_does_not_block(self):
        """Testa que tráfego normal não aciona bloqueio."""
        test_ip = "192.168.1.15"
        normal_request = "/index.html"
        
        self.mock_time = 20
        self._write_log_entry(test_ip, normal_request)

        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips)

    def test_already_blocked_ip_does_not_retrigger_block(self):
        """Um IP já bloqueado não deve acionar um novo bloqueio."""
        test_ip = "192.168.1.16"
        malicious_request = "/index.php?id=1%27+UNION+SELECT+1,2,3-- "
        
        # Bloqueia o IP
        self.mock_time = 1
        self._write_log_entry(test_ip, malicious_request)

        self.assertIn(test_ip, self.mock_firewall.blocked_ips)
        
        # Registra mais ataque do mesmo IP enquanto bloqueado
        self.mock_time = 2
        self._write_log_entry(test_ip, "/?q=<script>alert(2)</script>")
        
        # O tempo de desbloqueio deve ser o do primeiro bloqueio, não o do segundo

        self.assertEqual(self.handler.blocked_ips[test_ip], 1 + self.config['block_duration'])

if __name__ == '__main__':
    unittest.main()

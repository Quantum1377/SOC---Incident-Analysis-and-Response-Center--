import unittest
from unittest.mock import patch, mock_open, MagicMock
import time
import os
import shutil

# Importando o handler e a fábrica de firewall
from modulos_de_defesa.ssh_protection.monitor import SSHLogHandler
from modulos_de_defesa.firewall import MockFirewall

class TestSSHProtection(unittest.TestCase):

    def setUp(self):
        """Configura um ambiente de teste limpo antes de cada teste."""
        self.test_dir = "./test_logs"
        os.makedirs(self.test_dir, exist_ok=True)
        self.log_file_path = os.path.join(self.test_dir, "auth.log")

        # Garante que o arquivo de log esteja vazio para cada teste
        with open(self.log_file_path, "w") as f:
            f.write("")

        self.mock_firewall = MockFirewall()
        self.mock_event_client = MagicMock()
        self.config = {
            'log_file': self.log_file_path,
            'threshold': 3,
            'time_window': 60, # segundos
            'block_duration': 5, # segundos
            'firewall_type': 'mock'
        }
        # Instancia o handler para o teste
        self.handler = SSHLogHandler(self.config, self.mock_firewall, self.log_file_path, self.mock_event_client)
        
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

    def _write_log_entry(self, ip_address, success=False):
        """Escreve uma entrada de log de tentativa de login."""
        if success:
            log_entry = f"Dec 1 10:00:00 host sshd[123]: Accepted password for user from {ip_address} port 12345 ssh2"
        else:
            log_entry = f"Dec 1 10:00:00 host sshd[123]: Failed password for invalid user test from {ip_address} port 12345 ssh2"
        
        with open(self.log_file_path, "a") as f:
            f.write(log_entry + "\n")
        self.handler.check_new_lines() # Processa a nova linha imediatamente

    def test_ip_blocking_after_threshold(self):
        """Testa se um IP é bloqueado após exceder o limite de tentativas."""
        test_ip = "192.168.1.100"

        # Simula 2 tentativas falhas - abaixo do threshold
        self.mock_time = 1
        self._write_log_entry(test_ip)
        self.mock_time = 2
        self._write_log_entry(test_ip)
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Não deve estar bloqueado ainda

        # Simula a 3ª tentativa falha - atinge o threshold
        self.mock_time = 3
        self._write_log_entry(test_ip)
        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Deve estar bloqueado

    def test_ip_unblocking_after_duration(self):
        """Testa se um IP é desbloqueado automaticamente após a duração configurada."""
        test_ip = "192.168.1.101"

        # Simula tentativas falhas para bloquear o IP
        self.mock_time = 10
        self._write_log_entry(test_ip)
        self.mock_time = 11
        self._write_log_entry(test_ip)
        self.mock_time = 12
        self._write_log_entry(test_ip)
        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Deve estar bloqueado

        # Avança o tempo para antes do desbloqueio
        self.mock_time = 12 + self.config['block_duration'] - 1 # 1 segundo antes de expirar
        self.handler.cleanup_blocked_ips()
        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Ainda deve estar bloqueado

        # Avança o tempo para após o desbloqueio
        self.mock_time = 12 + self.config['block_duration'] + 1 # 1 segundo após expirar
        self.handler.cleanup_blocked_ips()
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Deve ter sido desbloqueado
        self.assertIn(test_ip, self.mock_firewall.unblocked_ips) # Deve estar na lista de desbloqueados do mock

    def test_multiple_ips_blocking(self):
        """Testa o bloqueio de múltiplos IPs independentemente."""
        ip1 = "192.168.1.102"
        ip2 = "192.168.1.103"

        # Bloqueia IP1
        self.mock_time = 20
        self._write_log_entry(ip1)
        self.mock_time = 21
        self._write_log_entry(ip1)
        self.mock_time = 22
        self._write_log_entry(ip1)
        self.assertIn(ip1, self.mock_firewall.blocked_ips)
        self.assertNotIn(ip2, self.mock_firewall.blocked_ips)

        # Bloqueia IP2
        self.mock_time = 23
        self._write_log_entry(ip2)
        self.mock_time = 24
        self._write_log_entry(ip2)
        self.mock_time = 25
        self._write_log_entry(ip2)
        self.assertIn(ip1, self.mock_firewall.blocked_ips)
        self.assertIn(ip2, self.mock_firewall.blocked_ips)
    
    def test_attempts_outside_time_window_do_not_block(self):
        """Tentativas fora da janela de tempo não devem contribuir para o bloqueio."""
        test_ip = "192.168.1.104"
        
        self.mock_time = 1
        self._write_log_entry(test_ip) # 1
        self.mock_time = 2
        self._write_log_entry(test_ip) # 2
        
        # Avança o tempo para que as tentativas anteriores expirem
        self.mock_time = 2 + self.config['time_window'] + 1 # Fora da janela
        self._write_log_entry(test_ip) # 3, mas 1 e 2 já expiraram
        
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Não deve bloquear
        
        # Mais tentativas dentro da nova janela de tempo
        self.mock_time = self.mock_time + 1
        self._write_log_entry(test_ip) # 2ª tentativa na nova janela
        self.mock_time = self.mock_time + 1
        self._write_log_entry(test_ip) # 3ª tentativa na nova janela - deve bloquear
        
        self.assertIn(test_ip, self.mock_firewall.blocked_ips)

    def test_successful_login_does_not_block(self):
        """Tentativas de login bem-sucedidas não devem levar a bloqueios."""
        test_ip = "192.168.1.105"
        self._write_log_entry(test_ip, success=True)
        self._write_log_entry(test_ip, success=True)
        self._write_log_entry(test_ip, success=True)
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips)

if __name__ == '__main__':
    unittest.main()

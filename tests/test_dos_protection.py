import unittest
from unittest.mock import patch, mock_open, MagicMock
import time
import os
import shutil

# Importando o handler e a fábrica de firewall
from modulos_de_defesa.dos_protection.monitor import DoSLogHandler
from modulos_de_defesa.firewall import MockFirewall

class TestDoSProtection(unittest.TestCase):

    def setUp(self):
        """Configura um ambiente de teste limpo antes de cada teste."""
        self.test_dir = "./test_logs_dos"
        os.makedirs(self.test_dir, exist_ok=True)
        self.log_file_path = os.path.join(self.test_dir, "access.log")

        # Garante que o arquivo de log esteja vazio para cada teste
        with open(self.log_file_path, "w") as f:
            f.write("")

        self.mock_firewall = MockFirewall()
        self.mock_event_client = MagicMock()
        self.config = {
            'log_file': self.log_file_path,
            'request_threshold': 5, # Pequeno para testes
            'time_window': 10,      # segundos
            'block_duration': 5,    # segundos
            'firewall_type': 'mock'
        }
        # Instancia o handler para o teste
        self.handler = DoSLogHandler(self.config, self.mock_firewall, self.log_file_path, self.mock_event_client)
        
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

    def _write_log_entry(self, ip_address, count=1):
        """Escreve uma entrada de log de acesso com o IP especificado."""
        for _ in range(count):
            log_entry = f"{ip_address} - - [{time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime(self.mock_time))}] \"GET /test HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\""
            with open(self.log_file_path, "a") as f:
                f.write(log_entry + "\n")
        self.handler.check_new_lines() # Processa a nova linha imediatamente

    def test_ip_blocking_after_threshold(self):
        """Testa se um IP é bloqueado após exceder o limite de requisições."""
        test_ip = "10.0.0.1"

        # Simula requisições abaixo do threshold
        self.mock_time = 1
        self._write_log_entry(test_ip, count=self.config['request_threshold'] - 1)
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Não deve estar bloqueado ainda

        # Simula requisição que atinge o threshold
        self.mock_time = 2
        self._write_log_entry(test_ip, count=1)
        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Deve estar bloqueado

    def test_ip_unblocking_after_duration(self):
        """Testa se um IP é desbloqueado automaticamente após a duração configurada."""
        test_ip = "10.0.0.2"

        # Bloqueia o IP
        self.mock_time = 10
        self._write_log_entry(test_ip, count=self.config['request_threshold'])
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

    def test_multiple_ips_blocking(self):
        """Testa o bloqueio de múltiplos IPs independentemente."""
        ip1 = "10.0.0.3"
        ip2 = "10.0.0.4"

        # Bloqueia IP1
        self.mock_time = 20
        self._write_log_entry(ip1, count=self.config['request_threshold'])
        self.assertIn(ip1, self.mock_firewall.blocked_ips)
        self.assertNotIn(ip2, self.mock_firewall.blocked_ips)

        # Bloqueia IP2
        self.mock_time = 21
        self._write_log_entry(ip2, count=self.config['request_threshold'])
        self.assertIn(ip1, self.mock_firewall.blocked_ips)
        self.assertIn(ip2, self.mock_firewall.blocked_ips)
    
    def test_requests_outside_time_window_do_not_block(self):
        """Requisições fora da janela de tempo não devem contribuir para o bloqueio."""
        test_ip = "10.0.0.5"
        
        self.mock_time = 1
        self._write_log_entry(test_ip, count=self.config['request_threshold'] - 1) # 4 requisições
        
        # Avança o tempo para que as requisições anteriores expirem
        self.mock_time = 1 + self.config['time_window'] + 1 # Fora da janela
        self._write_log_entry(test_ip, count=1) # 1 requisição, mas as 4 anteriores expiraram
        
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Não deve bloquear
        
        # Mais requisições dentro da nova janela de tempo para atingir o threshold
        self.mock_time = self.mock_time + 1
        self._write_log_entry(test_ip, count=self.config['request_threshold'] - 1) # Atinge o threshold
        
        self.assertIn(test_ip, self.mock_firewall.blocked_ips)

    def test_already_blocked_ip_does_not_retrigger_block(self):
        """Um IP já bloqueado não deve acionar um novo bloqueio."""
        test_ip = "10.0.0.6"
        
        # Bloqueia o IP
        self.mock_time = 1
        self._write_log_entry(test_ip, count=self.config['request_threshold'])
        self.assertIn(test_ip, self.mock_firewall.blocked_ips)
        
        # Registra mais requisições do mesmo IP enquanto bloqueado
        self.mock_time = 2
        self._write_log_entry(test_ip, count=self.config['request_threshold'])
        
        # A lista de bloqueados do mock firewall deve conter apenas uma entrada para este IP
        # e o 'block' não deve ter sido chamado novamente para o mesmo IP
        self.assertEqual(list(self.mock_firewall.blocked_ips)[0], test_ip)
        # O tempo de desbloqueio deve ser o do primeiro bloqueio, não o do segundo
        self.assertEqual(self.handler.blocked_ips[test_ip], 1 + self.config['block_duration'])

if __name__ == '__main__':
    unittest.main()

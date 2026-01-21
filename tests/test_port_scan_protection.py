import unittest
from unittest.mock import patch, mock_open, MagicMock
import time
import os
import shutil

# Importando o handler e a fábrica de firewall
from modulos_de_defesa.port_scan_protection.monitor import PortScanLogHandler
from modulos_de_defesa.firewall import MockFirewall

class TestPortScanProtection(unittest.TestCase):

    def setUp(self):
        """Configura um ambiente de teste limpo antes de cada teste."""
        self.test_dir = "./test_logs_portscan"
        os.makedirs(self.test_dir, exist_ok=True)
        self.log_file_path = os.path.join(self.test_dir, "ufw.log")

        # Garante que o arquivo de log esteja vazio para cada teste
        with open(self.log_file_path, "w") as f:
            f.write("")

        self.mock_firewall = MockFirewall()
        self.mock_event_client = MagicMock()
        self.config = {
            'log_file': self.log_file_path,
            'port_threshold': 3, # Pequeno para testes
            'time_window': 60,   # segundos
            'block_duration': 5, # segundos
            'firewall_type': 'mock'
        }
        # Instancia o handler para o teste
        self.handler = PortScanLogHandler(self.config, self.mock_firewall, self.log_file_path, self.mock_event_client)
        
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

    def _write_ufw_log_entry(self, ip_address, port):
        """Escreve uma entrada de log de bloqueio do UFW para simular tráfego."""
        log_entry = (
            f"Jan 1 00:00:00 host kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"SRC={ip_address} DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF "
            f"PROTO=TCP SPT=54321 DPT={port} WINDOW=29200 RES=0x00 SYN URGP=0"
        )
        with open(self.log_file_path, "a") as f:
            f.write(log_entry + "\n")
        self.handler.check_new_lines() # Processa a nova linha imediatamente

    def test_ip_blocking_after_port_threshold(self):
        """Testa se um IP é bloqueado após escanear o número de portas distintas configurado."""
        test_ip = "172.16.0.1"

        # Simula escaneamento de 2 portas distintas - abaixo do threshold
        self.mock_time = 1
        self._write_ufw_log_entry(test_ip, 80)
        self.mock_time = 2
        self._write_ufw_log_entry(test_ip, 443)
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Não deve estar bloqueado ainda

        # Simula escaneamento de 3ª porta distinta - atinge o threshold
        self.mock_time = 3
        self._write_ufw_log_entry(test_ip, 22)
        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Deve estar bloqueado

    def test_ip_unblocking_after_duration(self):
        """Testa se um IP é desbloqueado automaticamente após a duração configurada."""
        test_ip = "172.16.0.2"

        # Bloqueia o IP
        self.mock_time = 10
        self._write_ufw_log_entry(test_ip, 21)
        self.mock_time = 11
        self._write_ufw_log_entry(test_ip, 22)
        self.mock_time = 12
        self._write_ufw_log_entry(test_ip, 23)
        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Deve estar bloqueado

        # Avança o tempo para antes do desbloqueio
        self.mock_time = 12 + self.config['block_duration'] - 1
        self.handler.cleanup_blocked_ips()
        self.assertIn(test_ip, self.mock_firewall.blocked_ips) # Ainda deve estar bloqueado

        # Avança o tempo para após o desbloqueio
        self.mock_time = 12 + self.config['block_duration'] + 1
        self.handler.cleanup_blocked_ips()
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Deve ter sido desbloqueado
        self.assertIn(test_ip, self.mock_firewall.unblocked_ips) # Deve estar na lista de desbloqueados do mock

    def test_multiple_ips_blocking(self):
        """Testa o bloqueio de múltiplos IPs independentemente."""
        ip1 = "172.16.0.3"
        ip2 = "172.16.0.4"

        # Bloqueia IP1
        self.mock_time = 20
        self._write_ufw_log_entry(ip1, 25)
        self.mock_time = 21
        self._write_ufw_log_entry(ip1, 53)
        self.mock_time = 22
        self._write_ufw_log_entry(ip1, 110)
        self.assertIn(ip1, self.mock_firewall.blocked_ips)
        self.assertNotIn(ip2, self.mock_firewall.blocked_ips)

        # Bloqueia IP2
        self.mock_time = 23
        self._write_ufw_log_entry(ip2, 25)
        self.mock_time = 24
        self._write_ufw_log_entry(ip2, 53)
        self.mock_time = 25
        self._write_ufw_log_entry(ip2, 110)
        self.assertIn(ip1, self.mock_firewall.blocked_ips)
        self.assertIn(ip2, self.mock_firewall.blocked_ips)
    
    def test_ports_outside_time_window_do_not_block(self):
        """Portas escaneadas fora da janela de tempo não devem contribuir para o bloqueio."""
        test_ip = "172.16.0.5"
        
        self.mock_time = 1
        self._write_ufw_log_entry(test_ip, 1000)
        self.mock_time = 2
        self._write_ufw_log_entry(test_ip, 2000)
        
        # Avança o tempo para que as tentativas anteriores expirem
        self.mock_time = 2 + self.config['time_window'] + 1 # Fora da janela
        self._write_ufw_log_entry(test_ip, 3000) # 1ª porta na nova janela, as 2 anteriores expiraram
        
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Não deve bloquear
        
        # Mais portas dentro da nova janela de tempo
        self.mock_time = self.mock_time + 1
        self._write_ufw_log_entry(test_ip, 4000) # 2ª porta na nova janela
        self.mock_time = self.mock_time + 1
        self._write_ufw_log_entry(test_ip, 5000) # 3ª porta na nova janela - deve bloquear
        
        self.assertIn(test_ip, self.mock_firewall.blocked_ips)

    def test_same_port_multiple_times_does_not_block(self):
        """Escaneamento da mesma porta múltiplas vezes não deve acionar o bloqueio."""
        test_ip = "172.16.0.6"
        self.mock_time = 1
        self._write_ufw_log_entry(test_ip, 80)
        self.mock_time = 2
        self._write_ufw_log_entry(test_ip, 80) # Mesma porta
        self.mock_time = 3
        self._write_ufw_log_entry(test_ip, 80) # Mesma porta
        self.assertNotIn(test_ip, self.mock_firewall.blocked_ips) # Não deve bloquear

if __name__ == '__main__':
    unittest.main()

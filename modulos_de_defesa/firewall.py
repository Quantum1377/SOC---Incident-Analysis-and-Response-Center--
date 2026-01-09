import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Firewall:
    """Classe base abstrata para interações de firewall."""
    def block(self, ip_address, duration_seconds):
        raise NotImplementedError

    def unblock(self, ip_address):
        raise NotImplementedError

class UfwFirewall(Firewall):
    """Implementação de firewall para UFW (Uncomplicated Firewall)."""
    def block(self, ip_address, duration_seconds=None):
        """Bloqueia um IP. UFW não suporta durações diretamente na regra."""
        logging.info(f"UFW: Bloqueando IP {ip_address}.")
        # O desbloqueio terá que ser gerenciado externamente se a duração for necessária.
        return self._run_command(["sudo", "ufw", "insert", "1", "deny", "from", ip_address])

    def unblock(self, ip_address):
        """Desbloqueia um IP."""
        logging.info(f"UFW: Desbloqueando IP {ip_address}.")
        return self._run_command(["sudo", "ufw", "delete", "deny", "from", ip_address])

    def _run_command(self, command):
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            logging.info(f"Comando UFW executado com sucesso: {' '.join(command)}")
            if result.stdout:
                logging.info(f"Stdout: {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            logging.error("Erro: 'sudo' ou 'ufw' não encontrado. Verifique a instalação e o PATH.")
            return False
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao executar comando UFW: {e.Stderr.strip()}")
            return False

class IptablesFirewall(Firewall):
    """Implementação de firewall para iptables."""
    def block(self, ip_address, duration_seconds=None):
        """Bloqueia um IP."""
        logging.info(f"iptables: Bloqueando IP {ip_address}.")
        # O desbloqueio com 'at' é instável. A gestão de duração deve ser externa.
        return self._run_command(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])

    def unblock(self, ip_address):
        """Desbloqueia um IP."""
        logging.info(f"iptables: Desbloqueando IP {ip_address}.")
        return self._run_command(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"])

    def _run_command(self, command):
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            logging.info(f"Comando iptables executado com sucesso: {' '.join(command)}")
            if result.stdout:
                logging.info(f"Stdout: {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            logging.error("Erro: 'sudo' ou 'iptables' não encontrado. Verifique a instalação e o PATH.")
            return False
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao executar comando iptables: {e.Stderr.strip()}")
            return False

class MockFirewall(Firewall):
    """Implementação de firewall mock para testes."""
    def __init__(self):
        self.blocked_ips = set()
        self.unblocked_ips = set()

    def block(self, ip_address, duration_seconds=None):
        self.blocked_ips.add(ip_address)
        return True

    def unblock(self, ip_address):
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
        self.unblocked_ips.add(ip_address)
        return True

def get_firewall(firewall_type):
    """Fábrica para obter a implementação de firewall correta."""
    if firewall_type == "ufw":
        return UfwFirewall()
    elif firewall_type == "iptables":
        return IptablesFirewall()
    elif firewall_type == "mock":
        return MockFirewall()
    else:
        raise ValueError(f"Tipo de firewall desconhecido: {firewall_type}")

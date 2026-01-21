import os
import re
import time
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ..firewall import get_firewall, Firewall
from event_client_threaded import EventClientThreaded # MODIFIED: Import new client

class SSHLogHandler(FileSystemEventHandler):
    def __init__(self, config, firewall: Firewall, log_file_path: str, event_client: EventClientThreaded): # MODIFIED: Accept client
        self.config = config
        self.firewall = firewall
        self.log_file = log_file_path
        self.event_client = event_client # MODIFIED: Store client
        self.failed_attempts = defaultdict(lambda: deque())
        self.blocked_ips = {} # IP -> unblock_time

        # Regex para 'Failed password for user from IP'
        self.fail_regex = re.compile(
            r"Failed password for (?:invalid user )?.*? from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        )
        
        self.file = None
        self._open_log_file()

    def _open_log_file(self):
        """Abre o arquivo de log e posiciona o cursor no final."""
        try:
            # Se o arquivo já estiver aberto, não faça nada
            if self.file and not self.file.closed:
                return
            self.file = open(self.log_file, 'r')
            self.file.seek(0, 2)
        except FileNotFoundError:
            print(f"ERRO [SSH]: O arquivo de log '{self.log_file}' não foi encontrado.")
            self.file = None
        except Exception as e:
            print(f"ERRO [SSH]: Erro inesperado ao abrir o arquivo de log: {e}")
            self.file = None
            
    def on_modified(self, event):
        if event.src_path == self.log_file:
            self._open_log_file() # Garante que o arquivo esteja aberto
            self.check_new_lines()

    def check_new_lines(self):
        """Lê novas linhas e as processa."""
        if not self.file or self.file.closed:
            return
        
        lines = self.file.readlines()
        for line in lines:
            self.process_log_entry(line.strip())

    def process_log_entry(self, log_entry):
        match = self.fail_regex.search(log_entry)
        if not match:
            return

        ip_address = match.group(1)
        timestamp = time.time()

        # Limpa timestamps antigos da deque
        attempts = self.failed_attempts[ip_address]
        while attempts and (timestamp - attempts[0]) > self.config['time_window']:
            attempts.popleft()

        # Adiciona nova tentativa
        attempts.append(timestamp)

        # Verifica se o IP deve ser bloqueado
        if ip_address not in self.blocked_ips and len(attempts) >= self.config['threshold']:
            print(f"ALERTA [SSH]: Múltiplas falhas de login do IP {ip_address}. Possível força bruta.")
            
            # MODIFIED: Send event to event bus
            event_payload = {
                "source_ip": ip_address,
                "target_service": "ssh",
                "attempt_count": len(attempts),
                "time_window": self.config['time_window'],
                "severity": "high",
                "action": "block_attempt" # To trigger the SOAR playbook
            }
            self.event_client.send_event_threadsafe("ssh_brute_force_detected", event_payload)
            
            # O bloqueio agora será feito pelo SOAR. A lógica local pode ser desativada
            # ou mantida como fallback. Por enquanto, vamos manter.
            
            # Bloqueia o IP usando a abstração do firewall
            block_duration = self.config['block_duration']
            if self.firewall.block(ip_address, duration_seconds=block_duration):
                print(f"AÇÃO [SSH]: IP {ip_address} bloqueado por {block_duration} segundos.")
                # Adiciona na lista de bloqueados para evitar re-bloqueio
                self.blocked_ips[ip_address] = timestamp + block_duration
            else:
                print(f"FALHA [SSH]: Falha ao tentar bloquear o IP {ip_address}.")

            # Limpa as tentativas para este IP
            self.failed_attempts[ip_address].clear()

        # Limpa IPs da lista de bloqueados cujo tempo de bloqueio já expirou
        self.cleanup_blocked_ips()

    def cleanup_blocked_ips(self):
        current_time = time.time()
        expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() if current_time > unblock_time]
        for ip in expired_ips:
            print(f"INFO [SSH]: Período de bloqueio para o IP {ip} expirou.")
            # Desbloqueia o IP
            if self.firewall.unblock(ip):
                 print(f"AÇÃO [SSH]: IP {ip} desbloqueado.")
            else:
                 print(f"FALHA [SSH]: Falha ao tentar desbloquear o IP {ip}.")
            del self.blocked_ips[ip]

def start_monitor(config):
    """Inicia o monitoramento do log de autenticação para ataques de força bruta."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO [SSH]: 'log_file' para ssh_protection não definido no config.")
        return

    firewall_type = config.get('firewall_type', 'ufw')
    try:
        firewall = get_firewall(firewall_type)
    except ValueError as e:
        print(f"ERRO [SSH]: {e}")
        return

    # MODIFIED: Initialize and start the event client
    event_client = EventClientThreaded(name="SSHProtectionMonitor")
    # Small delay to ensure client can try to connect
    time.sleep(2)

    print(f"Iniciando monitor de SSH no arquivo: {log_file} com firewall: {firewall_type}")

    # MODIFIED: Pass client to handler
    event_handler = SSHLogHandler(config, firewall, log_file, event_client)
    observer = Observer()
    
    log_dir = os.path.dirname(log_file)
    # Garante que o diretório de log exista antes de iniciar o observer
    if not os.path.exists(log_dir):
        print(f"AVISO [SSH]: O diretório de log '{log_dir}' não existe. O monitoramento pode falhar.")
        # Pode-se optar por criar o diretório aqui, se desejado: os.makedirs(log_dir, exist_ok=True)
    
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de SSH ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            # Roda o cleanup periodicamente
            event_handler.cleanup_blocked_ips()
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nINFO [SSH]: Monitor de SSH interrompido.")
    finally:
        observer.stop()
        observer.join()
        event_client.close() # MODIFIED: Close client connection
        print("INFO [SSH]: Recursos liberados.")


if __name__ == '__main__':
    print("Este módulo foi feito para ser importado e executado pelo main.py")
    print("Para testar, configure o 'config.yaml' e execute o 'main.py'.")
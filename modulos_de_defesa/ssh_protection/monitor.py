import os
import re
import time
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .response import block_ip

class SSHLogHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.log_file = config['log_file']
        self.failed_attempts = defaultdict(lambda: deque())
        self.blocked_ips = {} # IP -> unblock_time

        # Regex para 'Failed password for user from IP'
        self.fail_regex = re.compile(
            r"Failed password for (?:invalid user )?.*? from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        )
        
        try:
            self.file = open(self.log_file, 'r')
            self.file.seek(0, 2)  # Vai para o final do arquivo
        except FileNotFoundError:
            print(f"ERRO [SSH]: O arquivo de log '{self.log_file}' não foi encontrado.")
            self.file = None

    def on_modified(self, event):
        if event.src_path == self.log_file and self.file:
            self.check_new_lines()

    def check_new_lines(self):
        """Lê novas linhas e as processa."""
        if not self.file:
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
            
            # Bloqueia o IP
            block_ip(
                ip_address, 
                duration_seconds=self.config['block_duration'],
                firewall_type=self.config.get('firewall_type', 'ufw')
            )
            
            # Adiciona na lista de bloqueados para evitar re-bloqueio
            self.blocked_ips[ip_address] = timestamp + self.config['block_duration']
            
            # Limpa as tentativas para este IP
            self.failed_attempts[ip_address].clear()

        # Limpa IPs da lista de bloqueados cujo tempo de bloqueio já expirou
        self.cleanup_blocked_ips()

    def cleanup_blocked_ips(self):
        current_time = time.time()
        expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() if current_time > unblock_time]
        for ip in expired_ips:
            print(f"INFO [SSH]: Período de bloqueio para o IP {ip} expirou.")
            del self.blocked_ips[ip]

def start_monitor(config):
    """Inicia o monitoramento do log de autenticação para ataques de força bruta."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO [SSH]: 'log_file' para ssh_protection não definido no config.")
        return

    print(f"Iniciando monitor de SSH no arquivo: {log_file}")

    event_handler = SSHLogHandler(config)
    observer = Observer()
    
    log_dir = os.path.dirname(log_file)
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de SSH ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            # Roda o cleanup periodicamente
            event_handler.cleanup_blocked_ips()
            time.sleep(60)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    print("Este módulo foi feito para ser importado e executado pelo main.py")
    print("Para testar, configure o 'config.yaml' e execute o 'main.py'.")
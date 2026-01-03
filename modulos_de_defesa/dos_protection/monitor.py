import time
import re
import os
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .response import block_ip

class DoSLogHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.log_file = config['log_file']
        
        # Estrutura para rastrear requisições: ip -> deque de timestamps
        self.ip_requests = defaultdict(lambda: deque())
        
        self.blocked_ips = {} # IP -> unblock_time

        # Regex para extrair IPs de logs de acesso do Apache/Nginx
        # Ex: 127.0.0.1 - - [21/Dec/2025:01:05:00 -0300] "GET /index.html HTTP/1.1" 200 42 "-" "Mozilla/5.0 (...)"
        self.log_regex = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        try:
            self.file = open(self.log_file, 'r')
            self.file.seek(0, 2)  # Vai para o final do arquivo
        except FileNotFoundError:
            print(f"ERRO [DoS]: O arquivo de log '{self.log_file}' não foi encontrado.")
            self.file = None

    def on_modified(self, event):
        if event.src_path == self.log_file and self.file:
            self.check_new_lines()

    def check_new_lines(self):
        if not self.file:
            return
        
        lines = self.file.readlines()
        for line in lines:
            self.process_log_entry(line.strip())

    def process_log_entry(self, log_entry):
        match = self.log_regex.search(log_entry)
        if not match:
            return

        ip_address = match.group(1)
        current_time = time.time()

        # Ignora IPs já bloqueados
        if ip_address in self.blocked_ips and self.blocked_ips[ip_address] > current_time:
            return

        # Adiciona a requisição atual
        self.ip_requests[ip_address].append(current_time)

        # Remove requisições antigas que estão fora da janela de tempo
        while self.ip_requests[ip_address] and \
              (current_time - self.ip_requests[ip_address][0]) > self.config['time_window']:
            self.ip_requests[ip_address].popleft()

        # Verifica se o threshold de requisições foi atingido
        if len(self.ip_requests[ip_address]) >= self.config['request_threshold']:
            print(f"ALERTA [DoS]: Ataque de DoS/HTTP Flood detectado do IP {ip_address}")
            print(f"  --> {len(self.ip_requests[ip_address])} requisições em {self.config['time_window']} segundos.")
            
            # Bloqueia o IP
            block_ip(
                ip_address,
                duration_seconds=self.config['block_duration'],
                firewall_type=self.config.get('firewall_type', 'ufw')
            )
            
            # Adiciona na lista de bloqueados e remove do rastreamento
            self.blocked_ips[ip_address] = current_time + self.config['block_duration']
            del self.ip_requests[ip_address]

    def cleanup_blocked_ips(self):
        """Remove IPs da lista de bloqueados cujo tempo expirou."""
        current_time = time.time()
        expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() if current_time > unblock_time]
        for ip in expired_ips:
            print(f"INFO [DoS]: Período de bloqueio para o IP {ip} expirou.")
            del self.blocked_ips[ip]

def start_monitor(config):
    """Inicia o monitoramento do log de acesso web para detecção de DoS/HTTP Flood."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO [DoS]: 'log_file' para dos_protection não definido no config.")
        return

    print(f"Iniciando monitor de DoS/HTTP Flood no arquivo: {log_file}")

    event_handler = DoSLogHandler(config)
    observer = Observer()
    
    log_dir = os.path.dirname(log_file)
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de DoS/HTTP Flood ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            event_handler.cleanup_blocked_ips()
            time.sleep(10) # Pausa para não consumir muito CPU
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    print("Este módulo foi feito para ser importado e executado pelo main.py")
    print("Para testar, configure o 'config.yaml' e execute o 'main.py'.")

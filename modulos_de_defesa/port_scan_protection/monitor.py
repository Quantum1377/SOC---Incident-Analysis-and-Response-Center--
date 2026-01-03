import time
import re
import os
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .response import block_ip

class PortScanLogHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.log_file = config['log_file']
        
        # Estrutura para rastrear tentativas: 
        # ip -> {'timestamp': first_seen, 'ports': {port1, port2, ...}}
        self.ip_attempts = defaultdict(lambda: {'timestamp': time.time(), 'ports': set()})
        
        self.blocked_ips = {} # IP -> unblock_time

        # Regex para logs do UFW (pode precisar de ajuste para outros formatos)
        # Ex: [UFW BLOCK] IN=... SRC=192.168.1.10 ... DPT=22 ...
        self.log_regex = re.compile(r"\[UFW BLOCK\].*SRC=([\d\.]+).*DPT=(\d+)")

        try:
            self.file = open(self.log_file, 'r')
            self.file.seek(0, 2)  # Vai para o final do arquivo
        except FileNotFoundError:
            print(f"ERRO [PortScan]: O arquivo de log '{self.log_file}' não foi encontrado.")
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
        port = int(match.group(2))
        current_time = time.time()

        # Ignora IPs já bloqueados
        if ip_address in self.blocked_ips and self.blocked_ips[ip_address] > current_time:
            return

        # Limpa o rastreamento de IPs antigos que não atingiram o threshold
        self.cleanup_old_attempts(current_time)

        # Adiciona a nova porta ao set do IP
        self.ip_attempts[ip_address]['ports'].add(port)

        # Verifica se o threshold foi atingido dentro da janela de tempo
        first_seen = self.ip_attempts[ip_address]['timestamp']
        if (current_time - first_seen) <= self.config['time_window']:
            if len(self.ip_attempts[ip_address]['ports']) >= self.config['port_threshold']:
                print(f"ALERTA [PortScan]: Varredura de portas detectada do IP {ip_address}")
                print(f"  --> Atingiu {len(self.ip_attempts[ip_address]['ports'])} portas distintas.")
                
                # Bloqueia o IP
                block_ip(
                    ip_address,
                    duration_seconds=self.config['block_duration'],
                    firewall_type=self.config.get('firewall_type', 'ufw')
                )
                
                # Adiciona na lista de bloqueados e remove do rastreamento
                self.blocked_ips[ip_address] = current_time + self.config['block_duration']
                del self.ip_attempts[ip_address]

    def cleanup_old_attempts(self, current_time):
        """Remove IPs do dicionário de tentativas se a janela de tempo expirou."""
        time_window = self.config['time_window']
        expired_ips = [
            ip for ip, data in self.ip_attempts.items() 
            if (current_time - data['timestamp']) > time_window
        ]
        for ip in expired_ips:
            del self.ip_attempts[ip]

def start_monitor(config):
    """Inicia o monitoramento do log do firewall para detecção de varredura de portas."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO [PortScan]: 'log_file' para port_scan_protection não definido no config.")
        return

    print(f"Iniciando monitor de varredura de portas no arquivo: {log_file}")

    event_handler = PortScanLogHandler(config)
    observer = Observer()
    
    log_dir = os.path.dirname(log_file)
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de varredura de portas ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            time.sleep(60) # Pausa para não consumir muito CPU
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    print("Este módulo foi feito para ser importado e executado pelo main.py")
    print("Para testar, configure o 'config.yaml' e execute o 'main.py'.")

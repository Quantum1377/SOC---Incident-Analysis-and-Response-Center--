import time
import re
import os
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ..firewall import get_firewall, Firewall
from event_client_threaded import EventClientThreaded # MODIFIED: Import new client

class DoSLogHandler(FileSystemEventHandler):
    def __init__(self, config, firewall: Firewall, log_file_path: str, event_client: EventClientThreaded): # MODIFIED: Accept client
        self.config = config
        self.firewall = firewall
        self.log_file = log_file_path
        self.event_client = event_client # MODIFIED: Store client
        
        # Estrutura para rastrear requisições: ip -> deque de timestamps
        self.ip_requests = defaultdict(lambda: deque())
        
        self.blocked_ips = {} # IP -> unblock_time

        # Regex para extrair IPs de logs de acesso do Apache/Nginx
        # Ex: 127.0.0.1 - - [21/Dec/2025:01:05:00 -0300] "GET /index.html HTTP/1.1" 200 42 "-" "Mozilla/5.0 (...)"
        self.log_regex = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

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
            print(f"ERRO [DoS]: O arquivo de log '{self.log_file}' não foi encontrado.")
            self.file = None
        except Exception as e:
            print(f"ERRO [DoS]: Erro inesperado ao abrir o arquivo de log: {e}")
            self.file = None

    def on_modified(self, event):
        if event.src_path == self.log_file:
            self._open_log_file() # Garante que o arquivo esteja aberto
            self.check_new_lines()

    def check_new_lines(self):
        if not self.file or self.file.closed:
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
        request_count = len(self.ip_requests[ip_address])
        if request_count >= self.config['request_threshold']:
            print(f"ALERTA [DoS]: Ataque de DoS/HTTP Flood detectado do IP {ip_address}")
            print(f"  --> {request_count} requisições em {self.config['time_window']} segundos.")
            
            # MODIFIED: Send event to event bus
            event_payload = {
                "source_ip": ip_address,
                "request_count": request_count,
                "time_window": self.config['time_window'],
                "severity": "critical"
            }
            self.event_client.send_event_threadsafe("dos_attack_detected", event_payload)

            # Bloqueia o IP
            block_duration = self.config['block_duration']
            if self.firewall.block(ip_address, duration_seconds=block_duration):
                print(f"AÇÃO [DoS]: IP {ip_address} bloqueado por {block_duration} segundos.")
                self.blocked_ips[ip_address] = current_time + block_duration
            else:
                print(f"FALHA [DoS]: Falha ao tentar bloquear o IP {ip_address}.")

            del self.ip_requests[ip_address]

    def cleanup_blocked_ips(self):
        """Remove IPs da lista de bloqueados cujo tempo expirou."""
        current_time = time.time()
        expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() if current_time > unblock_time]
        for ip in expired_ips:
            print(f"INFO [DoS]: Período de bloqueio para o IP {ip} expirou.")
            if self.firewall.unblock(ip):
                 print(f"AÇÃO [DoS]: IP {ip} desbloqueado.")
            else:
                 print(f"FALHA [DoS]: Falha ao tentar desbloquear o IP {ip}.")
            del self.blocked_ips[ip]

def start_monitor(config):
    """Inicia o monitoramento do log de acesso web para detecção de DoS/HTTP Flood."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO [DoS]: 'log_file' para dos_protection não definido no config.")
        return

    firewall_type = config.get('firewall_type', 'ufw')
    try:
        firewall = get_firewall(firewall_type)
    except ValueError as e:
        print(f"ERRO [DoS]: {e}")
        return

    # MODIFIED: Initialize and start the event client
    event_client = EventClientThreaded(name="DoSProtectionMonitor")
    time.sleep(2)

    print(f"Iniciando monitor de DoS/HTTP Flood no arquivo: {log_file} com firewall: {firewall_type}")

    # MODIFIED: Pass client to handler
    event_handler = DoSLogHandler(config, firewall, log_file, event_client)
    observer = Observer()
    
    log_dir = os.path.dirname(log_file)
    # Garante que o diretório de log exista antes de iniciar o observer
    if not os.path.exists(log_dir):
        print(f"AVISO [DoS]: O diretório de log '{log_dir}' não existe. O monitoramento pode falhar.")
    
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de DoS/HTTP Flood ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            event_handler.cleanup_blocked_ips()
            time.sleep(10) # Pausa para não consumir muito CPU
    except KeyboardInterrupt:
        print("\nINFO [DoS]: Monitor de DoS/HTTP Flood interrompido.")
    finally:
        observer.stop()
        observer.join()
        event_client.close() # MODIFIED: Close client connection
        print("INFO [DoS]: Recursos liberados.")


if __name__ == '__main__':
    print("Este módulo foi feito para ser importado e executado pelo main.py")
    print("Para testar, configure o 'config.yaml' e execute o 'main.py'.")

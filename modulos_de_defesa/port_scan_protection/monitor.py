import time
import re
import os
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ..firewall import get_firewall, Firewall
from event_client_threaded import EventClientThreaded # MODIFIED: Import new client

class PortScanLogHandler(FileSystemEventHandler):
    def __init__(self, config, firewall: Firewall, log_file_path: str, event_client: EventClientThreaded): # MODIFIED: Accept client
        self.config = config
        self.firewall = firewall
        self.log_file = log_file_path
        self.event_client = event_client # MODIFIED: Store client
        
        # Estrutura para rastrear tentativas: 
        # ip -> {'timestamp': first_seen, 'ports': {port1, port2, ...}}
        self.ip_attempts = defaultdict(lambda: {'timestamp': time.time(), 'ports': set()})
        
        self.blocked_ips = {} # IP -> unblock_time

        # Regex para logs do UFW (pode precisar de ajuste para outros formatos)
        # Ex: [UFW BLOCK] IN=... SRC=192.168.1.10 ... DPT=22 ...
        self.log_regex = re.compile(r"\[UFW BLOCK\].*SRC=([\d\.]+).*DPT=(\d+)")

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
            print(f"ERRO [PortScan]: O arquivo de log '{self.log_file}' não foi encontrado.")
            self.file = None
        except Exception as e:
            print(f"ERRO [PortScan]: Erro inesperado ao abrir o arquivo de log: {e}")
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
        first_seen = self.ip_attempts[ip_address].get('timestamp', current_time)
        self.ip_attempts[ip_address]['timestamp'] = first_seen # Garante que timestamp seja definido
        
        if (current_time - first_seen) <= self.config['time_window']:
            port_count = len(self.ip_attempts[ip_address]['ports'])
            if port_count >= self.config['port_threshold']:
                print(f"ALERTA [PortScan]: Varredura de portas detectada do IP {ip_address}")
                print(f"  --> Atingiu {port_count} portas distintas.")
                
                # MODIFIED: Send event to event bus
                event_payload = {
                    "source_ip": ip_address,
                    "port_count": port_count,
                    "ports_scanned": sorted(list(self.ip_attempts[ip_address]['ports'])),
                    "time_window": self.config['time_window'],
                    "severity": "medium"
                }
                self.event_client.send_event_threadsafe("port_scan_detected", event_payload)

                # Bloqueia o IP
                block_duration = self.config['block_duration']
                if self.firewall.block(ip_address, duration_seconds=block_duration):
                    print(f"AÇÃO [PortScan]: IP {ip_address} bloqueado por {block_duration} segundos.")
                    self.blocked_ips[ip_address] = current_time + block_duration
                else:
                    print(f"FALHA [PortScan]: Falha ao tentar bloquear o IP {ip_address}.")

                # Remove do rastreamento de tentativas para evitar re-bloqueio imediato
                del self.ip_attempts[ip_address]

    def cleanup_old_attempts(self, current_time):
        """Remove IPs do dicionário de tentativas se a janela de tempo expirou."""
        time_window = self.config['time_window']
        expired_ips = [
            ip for ip, data in list(self.ip_attempts.items()) # Use list para evitar RuntimeError durante iteração e exclusão
            if (current_time - data['timestamp']) > time_window
        ]
        for ip in expired_ips:
            del self.ip_attempts[ip]

    def cleanup_blocked_ips(self):
        """Remove IPs da lista de bloqueados cujo tempo expirou."""
        current_time = time.time()
        expired_ips = [ip for ip, unblock_time in list(self.blocked_ips.items()) if current_time > unblock_time]
        for ip in expired_ips:
            print(f"INFO [PortScan]: Período de bloqueio para o IP {ip} expirou.")
            if self.firewall.unblock(ip):
                 print(f"AÇÃO [PortScan]: IP {ip} desbloqueado.")
            else:
                 print(f"FALHA [PortScan]: Falha ao tentar desbloquear o IP {ip}.")
            del self.blocked_ips[ip]

def start_monitor(config):
    """Inicia o monitoramento do log do firewall para detecção de varredura de portas."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO [PortScan]: 'log_file' para port_scan_protection não definido no config.")
        return

    firewall_type = config.get('firewall_type', 'ufw')
    try:
        firewall = get_firewall(firewall_type)
    except ValueError as e:
        print(f"ERRO [PortScan]: {e}")
        return

    # MODIFIED: Initialize and start the event client
    event_client = EventClientThreaded(name="PortScanMonitor")
    time.sleep(2)

    print(f"Iniciando monitor de varredura de portas no arquivo: {log_file} com firewall: {firewall_type}")

    # MODIFIED: Pass client to handler
    event_handler = PortScanLogHandler(config, firewall, log_file, event_client)
    observer = Observer()
    
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        print(f"AVISO [PortScan]: O diretório de log '{log_dir}' não existe. O monitoramento pode falhar.")
    
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de varredura de portas ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            event_handler.cleanup_blocked_ips() # Chamada periódica para desbloqueio
            time.sleep(60) # Pausa para não consumir muito CPU
    except KeyboardInterrupt:
        print("\nINFO [PortScan]: Monitor de varredura de portas interrompido.")
    finally:
        observer.stop()
        observer.join()
        event_client.close() # MODIFIED: Close client connection
        print("INFO [PortScan]: Recursos liberados.")


if __name__ == '__main__':
    print("Este módulo foi feito para ser importado e executado pelo main.py")
    print("Para testar, configure o 'config.yaml' e execute o 'main.py'.")

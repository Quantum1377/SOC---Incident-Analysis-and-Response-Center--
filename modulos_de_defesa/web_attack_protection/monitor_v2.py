import time
import re
import os
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ..firewall import get_firewall, Firewall
from event_client_threaded import EventClientThreaded # MODIFIED: Import new client

# Regex para extrair o endereço IP (padrão de log combinado do Apache/Nginx)
IP_EXTRACT_REGEX = re.compile(r'^(\S+)')
# Regex para extrair a string da requisição HTTP entre aspas duplas
REQUEST_EXTRACT_REGEX = re.compile(r'"(GET|POST|PUT|DELETE|HEAD)\s(.+?)\sHTTP/\d\.\d"')

# Regex para detectar padrões de ataques web comuns
WEB_ATTACK_PATTERNS = {
    "SQL_INJECTION": re.compile(r"(\'|\"|%27|%22).*?(union|select|insert|update|delete|drop).*", re.IGNORECASE),
    "PATH_TRAVERSAL": re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
    "COMMAND_INJECTION": re.compile(r"(;|\`|\|\||&&)\s*(ls|dir|cat|whoami|id|uname)", re.IGNORECASE),
    "XSS": re.compile(r"<script>|<img src=.*onerror=.*>", re.IGNORECASE),
}

class WebAttackLogHandler(FileSystemEventHandler):
    def __init__(self, config, firewall: Firewall, log_file: str, event_client: EventClientThreaded): # MODIFIED: Accept client
        super().__init__()
        self.config = config
        self.firewall = firewall
        self.log_file = log_file
        self.event_client = event_client # MODIFIED: Store client
        self.blocked_ips = {}
        
        self.file = None
        self._open_log_file()

    def _open_log_file(self): # MODIFIED: New file handling logic
        """Abre o arquivo de log e posiciona o cursor no final."""
        try:
            if self.file and not self.file.closed:
                return
            self.file = open(self.log_file, 'r')
            self.file.seek(0, 2)
        except FileNotFoundError:
            print(f"ERRO [WebAttack]: O arquivo de log '{self.log_file}' não foi encontrado.")
            self.file = None
        except Exception as e:
            print(f"ERRO [WebAttack]: Erro inesperado ao abrir o arquivo de log: {e}")
            self.file = None

    def check_new_lines(self): # MODIFIED: Simplified logic
        """Lê e processa novas linhas do arquivo de log."""
        if not self.file or self.file.closed:
            return
        
        lines = self.file.readlines()
        for line in lines:
            if line.strip():
                self.process_line(line)

    def on_modified(self, event):
        if event.src_path == self.log_file:
            self._open_log_file() # Ensure file is open and at the end
            self.check_new_lines()

    def process_line(self, line):
        """Verifica uma única linha de log por padrões de ataque."""
        ip_match = IP_EXTRACT_REGEX.match(line)
        if not ip_match:
            return

        ip_address = ip_match.group(1)
        current_time = time.time()

        # Ignora IPs já bloqueados
        if ip_address in self.blocked_ips and self.blocked_ips[ip_address] > current_time:
            return

        request_match = REQUEST_EXTRACT_REGEX.search(line)
        if not request_match:
            return
        
        request_method = request_match.group(1)
        request_path = request_match.group(2)
        request_data = f"{request_method} {request_path}" # Combina para verificar padrões

        for attack_type, pattern in WEB_ATTACK_PATTERNS.items():
            if pattern.search(request_data): # Aplicar pattern à request_data
                print(f"ALERTA [WebAttack]: Possível ataque de '{attack_type}' detectado do IP: {ip_address}")
                print(f"  --> Linha do Log: {line}")
                
                # MODIFIED: Send event to event bus
                event_payload = {
                    "source_ip": ip_address,
                    "attack_type": attack_type,
                    "request": request_data,
                    "full_log_line": line.strip(),
                    "severity": "high"
                }
                self.event_client.send_event_threadsafe("web_attack_detected", event_payload)

                # Mantendo o bloqueio local por enquanto como fallback
                block_duration = self.config.get('block_duration', 3600)
                if self.firewall.block(ip_address, duration_seconds=block_duration):
                    print(f"AÇÃO [WebAttack]: IP {ip_address} bloqueado por {block_duration} segundos.")
                    self.blocked_ips[ip_address] = current_time + block_duration
                else:
                    print(f"FALHA [WebAttack]: Falha ao tentar bloquear o IP {ip_address}.")
                
                break # Process only the first detected attack type for this line

    def cleanup_blocked_ips(self):
        """Remove IPs da lista de bloqueados cujo tempo expirou."""
        current_time = time.time()
        expired_ips = [ip for ip, unblock_time in list(self.blocked_ips.items()) if current_time > unblock_time]
        for ip in expired_ips:
            print(f"INFO [WebAttack]: Período de bloqueio para o IP {ip} expirou.")
            if self.firewall.unblock(ip):
                 print(f"AÇÃO [WebAttack]: IP {ip} desbloqueado.")
            else:
                 print(f"FALHA [WebAttack]: Falha ao tentar desbloquear o IP {ip}.")
            del self.blocked_ips[ip]

def start_monitor(config):
    """Inicia o monitoramento do arquivo de log para ataques web."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO [WebAttack]: 'log_file' para web_attack_protection não definido no config.yaml")
        return

    firewall_type = config.get('firewall_type', 'ufw')
    try:
        firewall = get_firewall(firewall_type)
    except ValueError as e:
        print(f"ERRO [WebAttack]: {e}")
        return

    # MODIFIED: Initialize event client
    event_client = EventClientThreaded(name="WebAttackMonitor")
    time.sleep(2) # Allow time for connection

    print(f"Iniciando monitor de ataques web no arquivo: {log_file} com firewall: {firewall_type}")

    # MODIFIED: Pass client to handler
    event_handler = WebAttackLogHandler(config, firewall, log_file, event_client)
    observer = Observer()
    
    # Precisamos observar o diretório, não o arquivo diretamente, para compatibilidade
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir) or not os.path.exists(log_file):
        print(f"AVISO [WebAttack]: O diretório de log '{log_dir}' ou o arquivo '{log_file}' não existe. O monitoramento pode falhar.")
    
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de ataques web ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            event_handler.cleanup_blocked_ips() # Chamada periódica para desbloqueio
            time.sleep(60) # Reduced frequency
    except KeyboardInterrupt:
        print("\nINFO [WebAttack]: Monitor de ataques web interrompido.")
    finally:
        observer.stop()
        observer.join()
        event_client.close() # MODIFIED: Close client
        print("INFO [WebAttack]: Recursos liberados.")


if __name__ == '__main__':
    # Exemplo de como usar (requer um arquivo de log e configuração)
    print("Este módulo foi feito para ser importado e executado pelo main.py")
    # Para testar standalone, você precisaria criar um config dict e um arquivo de log.
    # Ex:
    # test_config = {
    #     'log_file': '/var/log/apache2/access.log', # ou outro log
    #     'block_duration': 60,
    #     'firewall_type': 'ufw'
    # }
    # import os
    # if not os.path.exists(test_config['log_file']):
    #     print(f"Arquivo de log de teste não encontrado: {test_config['log_file']}")
    # else:
    #     start_monitor(test_config)

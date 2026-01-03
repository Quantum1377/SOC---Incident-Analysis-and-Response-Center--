import time
import re
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .response import block_ip

# Regex para extrair o endereço IP (padrão de log combinado do Apache/Nginx)
IP_EXTRACT_REGEX = re.compile(r'^(\S+)')

# Regex para detectar padrões de ataques web comuns
WEB_ATTACK_PATTERNS = {
    "SQL_INJECTION": re.compile(r"(\'|\"|%27|%22).*(union|select|insert|update|delete|drop).*\s", re.IGNORECASE),
    "PATH_TRAVERSAL": re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
    "COMMAND_INJECTION": re.compile(r"(;|\`|\|\||&&)\s*(ls|dir|cat|whoami|id|uname)", re.IGNORECASE),
    "XSS": re.compile(r"<script>|<img src=.*onerror=.*>", re.IGNORECASE),
}

class WebAttackLogHandler(FileSystemEventHandler):
    def __init__(self, config, recent_ips):
        self.log_file = config['log_file']
        self.config = config
        self.recent_ips = recent_ips
        # Mantém o ponteiro da última posição lida no arquivo
        try:
            self.file = open(self.log_file, 'r')
            self.file.seek(0, 2)  # Vai para o final do arquivo
        except FileNotFoundError:
            print(f"ERRO: O arquivo de log '{self.log_file}' não foi encontrado.")
            self.file = None

    def on_modified(self, event):
        if event.src_path == self.log_file and self.file:
            self.check_new_lines()

    def check_new_lines(self):
        """Lê novas linhas adicionadas ao arquivo de log e as processa."""
        if not self.file:
            return
        
        lines = self.file.readlines() # Lê novas linhas desde a última posição
        for line in lines:
            self.process_line(line.strip())

    def process_line(self, line):
        """Verifica uma única linha de log por padrões de ataque."""
        ip_match = IP_EXTRACT_REGEX.match(line)
        if not ip_match:
            return

        ip_address = ip_match.group(1)

        # Evita processar o mesmo IP repetidamente em um curto período
        if ip_address in self.recent_ips:
            return

        for attack_type, pattern in WEB_ATTACK_PATTERNS.items():
            if pattern.search(line):
                print(f"ALERTA: Possível ataque de '{attack_type}' detectado do IP: {ip_address}")
                print(f"  --> Linha do Log: {line}")
                
                # Adiciona à lista de recentes para evitar spam de bloqueio
                self.recent_ips.add(ip_address)
                
                # Chama a função de resposta para bloquear o IP
                block_ip(
                    ip_address,
                    duration_seconds=self.config.get('block_duration', 3600),
                    firewall_type=self.config.get('firewall_type', 'ufw')
                )
                
                # Depois de encontrar um ataque e bloquear, não precisa verificar outros padrões na mesma linha
                break

def start_monitor(config):
    """Inicia o monitoramento do arquivo de log para ataques web."""
    log_file = config.get('log_file')
    if not log_file:
        print("ERRO: 'log_file' para web_attack_protection não definido no config.yaml")
        return

    print(f"Iniciando monitor de ataques web no arquivo: {log_file}")

    recent_ips = set() # Usado para rastrear IPs já processados

    event_handler = WebAttackLogHandler(config, recent_ips)
    observer = Observer()
    
    # Precisamos observar o diretório, não o arquivo diretamente, para compatibilidade
    log_dir = os.path.dirname(log_file)
    observer.schedule(event_handler, log_dir, recursive=False)
    
    observer.start()
    print("Monitor de ataques web ativo. Pressione Ctrl+C para parar.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

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

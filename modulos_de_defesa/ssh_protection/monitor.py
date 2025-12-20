import time
import re
import yaml
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Simulação da função de resposta (será substituída pela real no response.py)
def mock_block_ip(ip_address, duration):
    print(f"MOCK: Bloqueando IP {ip_address} por {duration} segundos.")
    # Aqui seria a chamada real para o response.py

class SSHLogHandler(FileSystemEventHandler):
    def __init__(self, config, response_callback):
        self.config = config
        self.response_callback = response_callback
        self.failed_attempts = defaultdict(lambda: deque(maxlen=self.config['threshold']))
        self.blocked_ips = {} # Dicionário para IPs bloqueados e seus horários de desbloqueio

        # Regex para extrair IPs de falhas de login SSH
        self.fail_regex = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+"
        )

    def on_modified(self, event):
        if not event.is_directory and event.src_path == self.config['log_file']:
            self.analyze_new_log_entries()

    def analyze_new_log_entries(self):
        with open(self.config['log_file'], 'r') as f:
            f.seek(0, 2) # Ir para o final do arquivo
            # Lê as últimas N linhas para garantir que pegamos entradas novas
            # Uma abordagem mais robusta usaria um cursor de arquivo ou seek(last_pos)
            # Para simplificar, vamos ler de novo o arquivo para cada modificação
            # Em produção, um tail -f ou similar seria mais eficiente
            f.seek(0)
            lines = f.readlines()
            for line in lines:
                self.process_log_entry(line.strip())

    def process_log_entry(self, log_entry):
        match = self.fail_regex.search(log_entry)
        if match:
            username = match.group(1)
            ip_address = match.group(2)
            timestamp = time.time()

            # Verificar se o IP já está bloqueado
            if ip_address in self.blocked_ips:
                if self.blocked_ips[ip_address] > timestamp:
                    # IP ainda bloqueado, ignorar novas tentativas por enquanto
                    return
                else:
                    # Tempo de bloqueio expirou, remover do bloqueados
                    del self.blocked_ips[ip_address]

            self.failed_attempts[ip_address].append(timestamp)
            self.check_for_bruteforce(ip_address)

    def check_for_bruteforce(self, ip_address):
        current_attempts = self.failed_attempts[ip_address]
        if len(current_attempts) >= self.config['threshold']:
            # Pega o timestamp da tentativa mais antiga dentro do limite
            oldest_attempt_time = current_attempts[0]
            
            # Verifica se todas as tentativas ocorreram dentro da janela de tempo
            if (time.time() - oldest_attempt_time) <= self.config['time_window']:
                print(f"ALERTA DE FORÇA BRUTA DETECTADO: IP {ip_address}")
                # Chamar a função de resposta real
                self.response_callback(ip_address, self.config['block_duration'])
                
                # Adicionar IP à lista de bloqueados temporariamente
                self.blocked_ips[ip_address] = time.time() + self.config['block_duration']
                
                # Limpar tentativas para este IP para evitar múltiplos bloqueios
                self.failed_attempts[ip_address].clear()

def start_monitor(config_path="config.yaml"):
    with open(config_path, 'r') as f:
        global_config = yaml.safe_load(f)

    ssh_config = global_config.get('ssh_protection', {})
    if not ssh_config.get('enabled', False):
        print("Módulo SSH Protection desabilitado na configuração.")
        return

    # Usar a mock_block_ip para testes iniciais
    event_handler = SSHLogHandler(ssh_config, mock_block_ip) 
    observer = Observer()
    observer.schedule(event_handler, ssh_config['log_file'], recursive=False)
    observer.start()
    print(f"Monitorando log SSH em: {ssh_config['log_file']} para ataques de força bruta.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Criar um arquivo de log simulado para teste
    test_log_file = "test_auth.log"
    with open(test_log_file, "w") as f:
        f.write("") # Garante que o arquivo existe e está vazio

    # Atualizar config.yaml para usar o arquivo de log de teste
    with open("config.yaml", 'r') as f:
        config_data = yaml.safe_load(f)
    config_data['ssh_protection']['log_file'] = test_log_file
    with open("config.yaml", 'w') as f:
        yaml.safe_dump(config_data, f)

    # Iniciar o monitor em um thread separado ou processo para poder escrever no log
    import threading
    monitor_thread = threading.Thread(target=start_monitor, args=("config.yaml",))
    monitor_thread.daemon = True
    monitor_thread.start()

    print("\n--- Simulando ataques de SSH (escrevendo no test_auth.log) ---")
    print("Abra 'test_auth.log' em outro terminal e adicione linhas para ver a detecção.")
    print("Exemplo de linha para adicionar: 'Failed password for user test from 192.168.1.100 port 12345'\n")

    # Exemplo de como você pode simular falhas escrevendo no log (em outro terminal ou script)
    # Por exemplo, execute em outro terminal:
    # echo "Failed password for user test from 192.168.1.100 port 12345" >> test_auth.log
    # Faça isso 5 vezes rapidamente para disparar o alerta.

    try:
        while True:
            time.sleep(10) # Manter o main thread vivo
    except KeyboardInterrupt:
        print("Monitoramento encerrado.")

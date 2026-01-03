import yaml
import threading
import time
from ssh_protection import monitor as ssh_monitor
from web_attack_protection import monitor as web_monitor
from port_scan_protection import monitor as port_scan_monitor
from dos_protection import monitor as dos_monitor

def load_config(config_path='config.yaml'):
    """Carrega o arquivo de configuração YAML."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        print(f"ERRO: Arquivo de configuração '{config_path}' não encontrado.")
        return None
    except yaml.YAMLError as e:
        print(f"ERRO: Erro ao fazer o parse do arquivo YAML: {e}")
        return None

def start_module_in_thread(module_name, monitor_function, config):
    """Inicia um módulo de monitoramento em uma nova thread."""
    print(f"Iniciando o módulo: {module_name}")
    thread = threading.Thread(target=monitor_function, args=(config,), daemon=True)
    thread.start()
    return thread

if __name__ == "__main__":
    print("--- Centro de Análise e Resposta a Incidentes ---")
    print("Carregando configuração...")
    
    config = load_config()
    
    if not config:
        print("Finalizando execução devido à falta de configuração.")
        exit(1)

    active_threads = []

    # Mapeamento de módulos para suas funções de monitoramento
    available_modules = {
        "ssh_protection": ssh_monitor.start_monitor,
        "web_attack_protection": web_monitor.start_monitor,
        "port_scan_protection": port_scan_monitor.start_monitor,
        "dos_protection": dos_monitor.start_monitor
    }

    print("Verificando e iniciando módulos de defesa ativados...")
    for name, start_func in available_modules.items():
        if name in config and config[name].get('enabled', False):
            module_config = config[name]
            thread = start_module_in_thread(name, start_func, module_config)
            active_threads.append(thread)
        else:
            print(f"Módulo '{name}' não encontrado na configuração ou desativado.")

    if not active_threads:
        print("Nenhum módulo de defesa foi ativado. O programa será encerrado.")
        exit(0)

    print("\n--- Todos os módulos ativos estão rodando em background ---")
    print("Pressione Ctrl+C para encerrar o programa principal.")

    try:
        # Mantém o programa principal rodando enquanto as threads dos monitores rodam em background
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nEncerrando o programa principal... Os monitores serão finalizados.")
    
    print("--- Programa finalizado. ---")

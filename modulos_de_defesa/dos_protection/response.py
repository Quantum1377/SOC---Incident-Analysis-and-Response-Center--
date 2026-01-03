import subprocess
import time
import os

def block_ip(ip_address, duration_seconds=3600, firewall_type="ufw"):
    """
    Bloqueia um endereço IP usando o firewall do sistema operacional.
    Suporta 'ufw' (Ubuntu/Debian) e 'iptables' (Linux genérico).
    """
    print(f"Iniciando bloqueio do IP: {ip_address} por {duration_seconds} segundos via {firewall_type}...")

    if firewall_type == "ufw":
        command = ["sudo", "ufw", "deny", "from", ip_address]
    elif firewall_type == "iptables":
        # Bloqueia o IP na chain INPUT
        command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        # Persistir a regra (pode variar dependendo da distro, exemplo para Debian/Ubuntu)
        # command_save = ["sudo", "netfilter-persistent", "save"] # ou iptables-save > /etc/iptables/rules.v4
    else:
        print(f"Tipo de firewall '{firewall_type}' não suportado ou configurado.")
        return False

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"Comando executado: {' '.join(command)}")
        print(f"Saída: {result.stdout.strip()}")
        if result.stderr:
            print(f"Erros: {result.stderr.strip()}")
        print(f"IP {ip_address} BLOQUEADO com sucesso no {firewall_type}.")

        # Para iptables, uma maneira simples de agendar o desbloqueio é com 'at'
        # Em um sistema real, você gerenciaria isso com um scheduler interno ou serviço
        if firewall_type == "iptables":
            # Agendar remoção da regra. Isso é um exemplo, 'at' pode não estar disponível ou configurado.
            # Uma solução mais robusta é necessária para produção.
            unblock_command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
            at_command = f'echo "{unblock_command}" | at now + {duration_seconds} seconds'
            print(f"Agendando desbloqueio: {at_command}")
            try:
                subprocess.run(at_command, shell=True, capture_output=True, text=True, check=True)
            except Exception as e:
                print(f"AVISO: Não foi possível agendar desbloqueio com 'at'. Remova manualmente se necessário. Erro: {e}")

        # Em um sistema real, o desbloqueio seria gerenciado por um scheduler ou por uma thread
        # que esperaria 'duration_seconds' e então executaria o comando de desbloqueio.
        # Por enquanto, apenas para demonstração, o bloqueio é persistente ou manual para iptables
        # e gerenciado pelo UFW se ele for configurado para remover regras temporárias.

        return True
    except subprocess.CalledProcessError as e:
        print(f"ERRO ao bloquear IP {ip_address}: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"ERRO: Comando de firewall ({firewall_type}) não encontrado. Verifique a instalação.")
        return False

def unblock_ip(ip_address, firewall_type="ufw"):
    """
    Desbloqueia um endereço IP (especialmente útil para iptables onde o bloqueio não expira automaticamente).
    """
    print(f"Iniciando desbloqueio do IP: {ip_address} via {firewall_type}...")

    if firewall_type == "ufw":
        command = ["sudo", "ufw", "delete", "deny", "from", ip_address]
    elif firewall_type == "iptables":
        command = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
    else:
        print(f"Tipo de firewall '{fireall_type}' não suportado ou configurado para desbloqueio.")
        return False

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"Comando executado: {' '.join(command)}")
        print(f"Saída: {result.stdout.strip()}")
        if result.stderr:
            print(f"Erros: {e.stderr.strip()}")
        print(f"IP {ip_address} DESBLOQUEADO com sucesso no {firewall_type}.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERRO ao desbloquear IP {ip_address}: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"ERRO: Comando de firewall ({firewall_type}) não encontrado. Verifique a instalação.")
        return False

if __name__ == "__main__":
    # Teste de bloqueio (requer sudo)
    # ATENÇÃO: Use um IP de teste, não o seu próprio!
    test_ip = "192.168.1.1" # Substitua por um IP que você deseja testar o bloqueio

    print("--- Testando UFW ---")
    # block_ip(test_ip, duration_seconds=60, firewall_type="ufw")
    # time.sleep(5)
    # unblock_ip(test_ip, firewall_type="ufw") # UFW gerencia bem as regras, mas podemos remover explicitamente

    print("\n--- Testando IPTables ---")
    # block_ip(test_ip, duration_seconds=60, firewall_type="iptables")
    # print(f"IP {test_ip} bloqueado. Verifique com 'sudo iptables -L INPUT -n'.")
    # print("Aguardando 65 segundos para desbloqueio (se 'at' funcionou e você descomentou a linha).")
    # time.sleep(65)
    # unblock_ip(test_ip, firewall_type="iptables") # Para iptables, o desbloqueio é geralmente manual ou agendado
    
    print("\nPara testar, descomente as chamadas de função acima e execute com sudo.")
    print("Lembre-se de ter 'ufw' ou 'iptables' configurados e os privilégios de sudo corretos.")

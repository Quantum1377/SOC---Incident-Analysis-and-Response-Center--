import requests
import json
import os

# Exemplo de script para buscar IoCs do MISP e enviar para um SIEM (Elasticsearch)

# --- Configurações ---
MISP_URL = os.getenv('MISP_URL', 'http://localhost:8080')
MISP_API_KEY = os.getenv('MISP_API_KEY', 'YOUR_MISP_API_KEY')
SIEM_URL = os.getenv('SIEM_URL', 'http://localhost:9200') # URL do Elasticsearch

HEADERS = {
    'Authorization': MISP_API_KEY,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

def fetch_misp_events():
    """
    Busca os eventos mais recentes do MISP.
    """
    endpoint = f"{MISP_URL}/events/restSearch/all"
    try:
        response = requests.post(endpoint, headers=HEADERS, json={"last": "1d"}) # Último dia
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erro ao buscar eventos do MISP: {e}")
        return None

def send_ioc_to_siem(ioc_data):
    """
    Envia um IoC para o SIEM (Elasticsearch).
    """
    index_name = "misp_iocs"
    endpoint = f"{SIEM_URL}/{index_name}/_doc"
    try:
        response = requests.post(endpoint, headers={'Content-Type': 'application/json'}, data=json.dumps(ioc_data))
        response.raise_for_status()
        print(f"IoC enviado ao SIEM: {ioc_data.get('value')}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erro ao enviar IoC para o SIEM: {e}")
        return None

def main():
    print("Iniciando a sincronização MISP-SIEM...")
    events_data = fetch_misp_events()

    if events_data and 'response' in events_data and 'Event' in events_data['response']:
        for event in events_data['response']['Event']:
            for attribute in event.get('Attribute', []):
                ioc = {
                    "misp_event_id": event.get('id'),
                    "misp_event_info": event.get('info'),
                    "category": attribute.get('category'),
                    "type": attribute.get('type'),
                    "value": attribute.get('value'),
                    "timestamp": attribute.get('timestamp'),
                    "source": "MISP"
                }
                send_ioc_to_siem(ioc)
    else:
        print("Nenhum evento encontrado ou erro na resposta do MISP.")

    print("Sincronização MISP-SIEM concluída.")

if __name__ == "__main__":
    main()

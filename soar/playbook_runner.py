import os
import yaml
import json
import time
import threading
import asyncio
from collections import defaultdict
from event_client import EventClient # Assumindo que event_client pode ser usado como base
from modulos_de_defesa.firewall import get_firewall, Firewall, MockFirewall # Usaremos isso para ações de firewall

class PlaybookRunner:
    def __init__(self, playbooks_dir, event_bus_host='localhost', event_bus_port=9999):
        self.playbooks_dir = playbooks_dir
        self.event_bus_host = event_bus_host
        self.event_bus_port = event_bus_port
        self.event_client = None # Will be initialized asynchronously
        self._reader = None
        self._writer = None
        self._load_playbooks()
        self.action_handlers = {
            "firewall_block": self._handle_firewall_block,
            "siem_log": self._handle_siem_log,
            "notification": self._handle_notification,
            # Adicione outros tipos de ação aqui
        }
        # Dicionário para armazenar instâncias de firewall por tipo, para reutilização
        self.firewall_instances = {}

    def _load_playbooks(self):
        print(f"Loading playbooks from: {self.playbooks_dir}")
        for root, _, files in os.walk(self.playbooks_dir):
            for file in files:
                if file.endswith(('.yaml', '.yml')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r') as f:
                            playbook_data = yaml.safe_load(f)
                            if playbook_data and playbook_data.get('enabled', False):
                                self.playbooks.append(playbook_data)
                                print(f"Loaded playbook: {playbook_data.get('name', file)}")
                    except Exception as e:
                        print(f"Error loading playbook {filepath}: {e}")
        print(f"Loaded {len(self.playbooks)} active playbooks.")

    def _get_firewall_instance(self, firewall_type):
        if firewall_type not in self.firewall_instances:
            try:
                self.firewall_instances[firewall_type] = get_firewall(firewall_type)
            except ValueError as e:
                print(f"ERROR: Could not get firewall instance for type {firewall_type}: {e}")
                return None
        return self.firewall_instances[firewall_type]

    def _handle_firewall_block(self, event, action_params):
        ip_address = action_params.get('ip_address')
        duration_seconds = action_params.get('duration_seconds', 3600)
        firewall_type = action_params.get('firewall_type', 'ufw')
        
        if not ip_address:
            print(f"ERROR: Firewall block action missing 'ip_address' in event: {event}")
            return False

        firewall = self._get_firewall_instance(firewall_type)
        if firewall:
            print(f"Attempting to block IP {ip_address} for {duration_seconds}s via {firewall_type}...")
            if firewall.block(ip_address, duration_seconds=duration_seconds):
                print(f"Successfully blocked IP {ip_address}.")
                return True
            else:
                print(f"Failed to block IP {ip_address}.")
                return False
        return False

    def _handle_siem_log(self, event, action_params):
        message = action_params.get('message', 'SOAR action log')
        severity = action_params.get('severity', 'info')
        # Em um ambiente real, enviaria para o SIEM (Elasticsearch/Wazuh)
        print(f"SIEM LOG (Severity: {severity}): {message}. Original event: {event}")
        return True

    def _handle_notification(self, event, action_params):
        to = action_params.get('to')
        subject = action_params.get('subject', 'SOAR Notification')
        body = action_params.get('body', 'No details provided.')
        
        if not to:
            print(f"ERROR: Notification action missing 'to' recipient.")
            return False
        
        # Em um ambiente real, enviaria um e-mail, SMS, Slack, etc.
        print(f"NOTIFICATION to {to}: Subject='{subject}', Body='{body}'. Original event: {event}")
        return True

    def _evaluate_condition(self, event_payload, condition):
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')

        event_value = event_payload.get(field)

        if operator == "==":
            return str(event_value) == str(value)
        elif operator == "!=":
            return str(event_value) != str(value)
        elif operator == ">=":
            return float(event_value) >= float(value)
        elif operator == "<=":
            return float(event_value) <= float(value)
        elif operator == ">":
            return float(event_value) > float(value)
        elif operator == "<":
            return float(event_value) < float(value)
        # Adicionar outros operadores conforme necessário
        return False

    async def _process_event(self, event_json):
        try:
            event = json.loads(event_json)
            event_type = event.get('type')
            event_payload = event.get('payload', {})
            print(f"Received event: Type='{event_type}', Payload={event_payload}")

            for playbook in self.playbooks:
                if playbook.get('trigger', {}).get('event_type') == event_type:
                    conditions_met = True
                    for condition in playbook['trigger'].get('conditions', []):
                        if not self._evaluate_condition(event_payload, condition):
                            conditions_met = False
                            break
                    
                    if conditions_met:
                        print(f"Playbook '{playbook['name']}' triggered by event {event_type}.")
                        for action in playbook.get('actions', []):
                            action_type = action.get('type')
                            action_params = action.get('parameters', {})
                            
                            # Substituir placeholders como {{ event.source_ip }}
                            # Simples substituição por enquanto, pode ser mais robusto com Jinja2
                            templated_action_params = {}
                            for k, v in action_params.items():
                                if isinstance(v, str) and '{{ event.' in v:
                                    # Exemplo: {{ event.source_ip }}
                                    field_name = v.replace('{{ event.', '').replace(' }}', '').strip()
                                    templated_action_params[k] = event_payload.get(field_name, v) # Fallback to original if not found
                                else:
                                    templated_action_params[k] = v

                            handler = self.action_handlers.get(action_type)
                            if handler:
                                success = handler(event, templated_action_params)
                                if success:
                                    for on_success_action in action.get('on_success', []):
                                        success_handler = self.action_handlers.get(on_success_action.get('type'))
                                        if success_handler:
                                            # Substituir placeholders nos parâmetros on_success também
                                            templated_success_params = {}
                                            for k, v in on_success_action.get('parameters', {}).items():
                                                if isinstance(v, str) and '{{ event.' in v:
                                                    field_name = v.replace('{{ event.', '').replace(' }}', '').strip()
                                                    templated_success_params[k] = event_payload.get(field_name, v)
                                                else:
                                                    templated_success_params[k] = v
                                            success_handler(event, templated_success_params)
                                else:
                                    for on_failure_action in action.get('on_failure', []):
                                        failure_handler = self.action_handlers.get(on_failure_action.get('type'))
                                        if failure_handler:
                                            # Substituir placeholders nos parâmetros on_failure também
                                            templated_failure_params = {}
                                            for k, v in on_failure_action.get('parameters', {}).items():
                                                if isinstance(v, str) and '{{ event.' in v:
                                                    field_name = v.replace('{{ event.', '').replace(' }}', '').strip()
                                                    templated_failure_params[k] = event_payload.get(field_name, v)
                                                else:
                                                    templated_failure_params[k] = v
                                            failure_handler(event, templated_failure_params)
                            else:
                                print(f"WARNING: Unknown action type '{action_type}' in playbook '{playbook['name']}'")
        except Exception as e:
            print(f"ERROR processing event: {e}. Event JSON: {event_json}")

    async def _listen_and_process_events(self):
        try:
            while True:
                data = await self._reader.readline()
                if not data:
                    print("Event bus disconnected.")
                    break
                message = data.decode().strip()
                await self._process_event(message)
        except asyncio.CancelledError:
            print("Event listener task cancelled.")
        except Exception as e:
            print(f"ERROR listening for events: {e}")
        finally:
            print("Event listener stopped.")

    async def start(self):
        print("SOAR Playbook Runner starting...")
        print("Connecting to Event Bus...")
        
        self.event_client = EventClient("PlaybookRunner", self.event_bus_host, self.event_bus_port)
        self._reader, self._writer = await self.event_client.connect()

        if self._reader and self._writer:
            print("Successfully connected to Event Bus. Listening for events.")
            listener_task = asyncio.create_task(self._listen_and_process_events())
            try:
                # Keep the main task alive
                await asyncio.Future()
            except asyncio.CancelledError:
                print("Main runner task cancelled.")
            finally:
                listener_task.cancel()
                await listener_task
                await self.event_client.close()
        else:
            print("Failed to connect to Event Bus. Exiting.")

if __name__ == "__main__":
    playbooks_path = os.path.join(os.path.dirname(__file__), 'playbooks')
    runner = PlaybookRunner(playbooks_dir=playbooks_path, event_bus_host='localhost', event_bus_port=9999)
    try:
        asyncio.run(runner.start())
    except KeyboardInterrupt:
        print("\nSOAR Playbook Runner shutting down.")

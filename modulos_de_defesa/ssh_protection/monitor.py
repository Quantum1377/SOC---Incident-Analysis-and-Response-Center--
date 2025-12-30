
import asyncio
import time
import re
import yaml
import json
import logging
from collections import defaultdict, deque

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

EVENT_BUS_HOST = '127.0.0.1'
EVENT_BUS_PORT = 9999
CLIENT_NAME = 'SSH-Monitor'

class SSHMonitor:
    def __init__(self, config):
        self.config = config
        self.failed_attempts = defaultdict(lambda: deque(maxlen=self.config['threshold']))
        self.blocked_ips = {}
        self.fail_regex = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+"
        )
        self._writer = None
        self._shutdown = asyncio.Event()
        self.logger = logging.getLogger(CLIENT_NAME)

    async def connect_to_bus(self):
        try:
            reader, self._writer = await asyncio.open_connection(EVENT_BUS_HOST, EVENT_BUS_PORT)
            self.logger.info("Connected to event bus.")
            return reader
        except ConnectionRefusedError:
            self.logger.error("Connection to event bus refused.")
            return None

    async def publish_alert(self, ip_address):
        alert_event = {
            "source": CLIENT_NAME,
            "type": "SSH_ALERT",
            "payload": {
                "message": f"Brute-force attack detected from IP: {ip_address}",
                "ip_address": ip_address,
                "block_duration": self.config['block_duration']
            }
        }
        message = json.dumps(alert_event) + "\n"
        if self._writer:
            self._writer.write(message.encode())
            await self._writer.drain()
            self.logger.info(f"Published SSH_ALERT for IP: {ip_address}")

    def process_log_entry(self, log_entry):
        match = self.fail_regex.search(log_entry)
        if match:
            ip_address = match.group(2)
            timestamp = time.time()

            if ip_address in self.blocked_ips and self.blocked_ips[ip_address] > timestamp:
                return

            if ip_address in self.blocked_ips:
                 del self.blocked_ips[ip_address]


            self.failed_attempts[ip_address].append(timestamp)
            
            # Check for brute-force attack
            attempts = self.failed_attempts[ip_address]
            if len(attempts) >= self.config['threshold']:
                if (timestamp - attempts[0]) <= self.config['time_window']:
                    self.logger.warning(f"Brute-force detected from {ip_address}. Publishing alert.")
                    # Run the alert publishing as a fire-and-forget task
                    asyncio.create_task(self.publish_alert(ip_address))
                    self.blocked_ips[ip_address] = timestamp + self.config['block_duration']
                    attempts.clear()

    async def listen_for_events(self):
        reader = await self.connect_to_bus()
        if not reader:
            self._shutdown.set()
            return

        while not self._shutdown.is_set():
            try:
                data = await reader.readline()
                if not data:
                    self.logger.warning("Disconnected from event bus.")
                    self._shutdown.set()
                    break

                message = data.decode().strip()
                try:
                    event = json.loads(message)
                    # Process only log entries relevant to SSH
                    if event.get("type") == "LOG_ENTRY":
                        self.process_log_entry(event.get("payload", ""))
                    elif event.get("payload") == f"SHUTDOWN:{CLIENT_NAME}":
                         self.logger.info("Shutdown command received. Exiting.")
                         self._shutdown.set()

                except json.JSONDecodeError:
                    # Ignore messages that are not valid JSON
                    pass

            except ConnectionError:
                self.logger.error("Connection to event bus lost.")
                self._shutdown.set()
            except Exception as e:
                self.logger.error(f"An error occurred while listening for events: {e}")
                self._shutdown.set()
        
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()


async def main():
    try:
        with open("modulos_de_defesa/config.yaml", 'r') as f:
            global_config = yaml.safe_load(f)
    except FileNotFoundError:
        logging.error("config.yaml not found. Please ensure it exists.")
        return

    ssh_config = global_config.get('ssh_protection', {})
    if not ssh_config.get('enabled', False):
        logging.info("SSH Protection module is disabled in the configuration.")
        return

    monitor = SSHMonitor(ssh_config)
    await monitor.listen_for_events()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("SSH Monitor shutting down.")

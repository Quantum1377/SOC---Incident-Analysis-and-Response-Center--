import asyncio
import psutil
import time
import json
import logging
import platform

import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Event Bus Configuration
EVENT_BUS_HOST = os.environ.get('EVENT_BUS_HOST', '127.0.0.1')
EVENT_BUS_PORT = 9999

class EDRClient:
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self._reader = None
        self._writer = None
        self._shutdown = asyncio.Event()

    async def connect(self):
        try:
            self._reader, self._writer = await asyncio.open_connection(EVENT_BUS_HOST, EVENT_BUS_PORT)
            logging.info(f"EDR Agent {self.agent_id} connected to event bus.")
            return True
        except ConnectionRefusedError:
            logging.error("Connection to event bus refused. Is it running?")
            return False
        except Exception as e:
            logging.error(f"Failed to connect to event bus: {e}")
            return False

    async def listen_for_commands(self):
        try:
            while not self._shutdown.is_set():
                data = await self._reader.readline()
                if not data:
                    logging.warning("Disconnected from event bus.")
                    self._shutdown.set()
                    break
                
                message = data.decode().strip()
                logging.info(f"Received command: {message}")
                
                # Example: Shutdown command
                if message == f"SHUTDOWN:{self.agent_id}":
                    logging.info("Shutdown command received. Terminating agent.")
                    self._shutdown.set()

        except asyncio.CancelledError:
            logging.info("Listener task cancelled.")
        except Exception as e:
            logging.error(f"Error in command listener: {e}")
            self._shutdown.set()

    async def send_data(self, data):
        if self._writer:
            try:
                # Add metadata to identify the event type
                event = {
                    "source": self.agent_id,
                    "type": "EDR_DATA",
                    "payload": data
                }
                message = json.dumps(event) + "\n"
                self._writer.write(message.encode())
                await self._writer.drain()
                logging.info("Successfully sent data to event bus.")
            except ConnectionError:
                logging.error("Connection to event bus lost.")
                self._shutdown.set()

    async def close(self):
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
        logging.info("Connection closed.")

def get_process_info():
    """Collects information about running processes."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username']):
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'create_time', 'username'])
            # Convert create_time to a serializable format if it's not already
            if isinstance(pinfo['create_time'], float):
                 pinfo['create_time'] = time.ctime(pinfo['create_time'])
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def get_network_connections():
    """Collects information about active network connections."""
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            process_name = "N/A"
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Ensure laddr and raddr are serializable
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

            conn_info = {
                'fd': conn.fd,
                'family': str(conn.family),
                'type': str(conn.type),
                'laddr': laddr,
                'raddr': raddr,
                'status': conn.status,
                'pid': conn.pid,
                'process_name': process_name
            }
            connections.append(conn_info)
        except (psutil.AccessDenied):
            pass
    return connections

def collect_system_data(agent_id):
    """Collects all relevant system data."""
    return {
        'agent_id': agent_id,
        'timestamp': time.time(),
        'processes': get_process_info(),
        'network_connections': get_network_connections()
    }

async def main():
    agent_id = f"EDR-AGENT-{platform.node()}"
    client = EDRClient(agent_id)
    
    if not await client.connect():
        return

    # Start the command listener in the background
    listener_task = asyncio.create_task(client.listen_for_commands())

    try:
        while not client._shutdown.is_set():
            logging.info("Collecting system data...")
            system_data = collect_system_data(agent_id)
            await client.send_data(system_data)
            
            # Wait for 5 seconds or until a shutdown is requested
            try:
                await asyncio.wait_for(client._shutdown.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass # This is expected, continue the loop

    except asyncio.CancelledError:
        logging.info("Main task cancelled.")
    finally:
        listener_task.cancel()
        await client.close()
        logging.info("EDR Agent has been shut down.")


if __name__ == "__main__":
    logging.info("EDR Agent starting.")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("EDR Agent stopped by user.")

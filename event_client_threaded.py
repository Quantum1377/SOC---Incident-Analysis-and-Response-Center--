import asyncio
import threading
import logging
import ssl
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class EventClientThreaded:
    def __init__(self, name, host='127.0.0.1', port=9999, text_widget=None):
        self.name = name
        self._host = host
        self._port = port
        self.logger = logging.getLogger(f'EventClient-{name}')
        self._writer = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self.start_client()

    def _create_ssl_context(self):
        """Creates an SSL context for the client."""
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # Assuming the cert is in secure_storage relative to the project root
        cert_path = "secure_storage/cert.pem"
        try:
            ssl_context.load_verify_locations(cafile=cert_path)
            return ssl_context
        except FileNotFoundError:
            self.logger.error(f"SSL certificate not found at {cert_path}. Make sure the path is correct.")
            return None
        except ssl.SSLError as e:
            self.logger.error(f"SSL Error. Make sure the certificate is valid. Details: {e}")
            return None


    def start_client(self):
        asyncio.run_coroutine_threadsafe(self._run(), self._loop)

    async def _run(self):
        ssl_context = self._create_ssl_context()
        if not ssl_context:
            self.logger.error("Could not create SSL context. Client will not connect.")
            return

        try:
            reader, writer = await asyncio.open_connection(
                self._host, self._port, ssl=ssl_context
            )
            self._writer = writer
            self.logger.info(f"Client {self.name} connected to event bus.")
            # This client is for sending, so we don't start a listener loop here.
        except ConnectionRefusedError:
            self.logger.error(f"Connection refused for {self.name}. Is the event bus server running?")
        except Exception as e:
            self.logger.error(f"Error connecting client {self.name}: {e}")

    async def _send_message(self, message: str):
        if self._writer and not self._writer.is_closing():
            self.logger.info(f"Sending: {message.strip()}")
            self._writer.write(message.encode())
            await self._writer.drain()
        else:
            self.logger.warning(f"Client {self.name} not connected or writer is closed. Cannot send message.")

    def send_message_threadsafe(self, message: str):
        """Schedules the async send_message to run in the event loop thread."""
        asyncio.run_coroutine_threadsafe(self._send_message(message), self._loop)
    
    def send_event_threadsafe(self, event_type: str, payload: dict):
        """Constructs a JSON event and sends it thread-safely."""
        event = {
            "source": self.name,
            "type": event_type,
            "payload": payload
        }
        message = json.dumps(event) + "\n"
        self.send_message_threadsafe(message)

    def close(self):
        if self._writer:
            self._loop.call_soon_threadsafe(self._writer.close)
        
        # Stop the loop and wait for the thread to finish
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()
        self.logger.info(f"Client {self.name} connection closed and thread stopped.")

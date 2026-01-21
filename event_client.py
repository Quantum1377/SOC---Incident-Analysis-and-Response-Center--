
import asyncio
import logging
import ssl

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class EventClient:
    def __init__(self, name, host='127.0.0.1', port=9999):
        self.name = name
        self._host = host
        self._port = port
        self.logger = logging.getLogger(f'EventClient-{name}')
        self._writer = None

    def _create_ssl_context(self):
        """Creates an SSL context for the client."""
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(
            cafile="secure_storage/cert.pem"
        )
        return ssl_context

    async def connect(self):
        """Connects the client to the event bus."""
        try:
            ssl_context = self._create_ssl_context() # New: Create SSL context
            reader, writer = await asyncio.open_connection(
                self._host, self._port, ssl=ssl_context # New: Pass SSL context
            )
            self._writer = writer
            self.logger.info(f"Client {self.name} connected to event bus.")
            return reader, writer
        except ConnectionRefusedError:
            self.logger.error(f"Connection refused. Is the event bus server running on {self._host}:{self._port}?")
            return None, None
        except Exception as e:
            self.logger.error(f"Error connecting client {self.name}: {e}")
            return None, None

    async def send_message(self, message: str):
        """Sends a message to the event bus."""
        if self._writer:
            full_message = f"[{self.name}] {message}\n"
            self.logger.info(f"Sending: {full_message.strip()}")
            self._writer.write(full_message.encode())
            await self._writer.drain()
        else:
            self.logger.warning(f"Client {self.name} not connected. Cannot send message.")

    async def listen_for_messages(self, reader: asyncio.StreamReader):
        """Listens for and logs messages from the event bus."""
        try:
            while True:
                data = await reader.readline()
                if not data:
                    self.logger.info(f"Event bus disconnected from client {self.name}.")
                    break
                message = data.decode().strip()
                self.logger.info(f"Received: {message}")
        except ConnectionResetError:
            self.logger.warning(f"Event bus reset connection with client {self.name}.")
        except Exception as e:
            self.logger.error(f"Error listening for messages for client {self.name}: {e}")

    async def close(self):
        """Closes the client connection."""
        if self._writer:
            self.logger.info(f"Closing connection for client {self.name}.")
            self._writer.close()
            await self._writer.wait_closed()

async def main():
    client1 = EventClient("TestClient1")
    reader1, writer1 = await client1.connect()
    
    if reader1 and writer1:
        # Start listening in a separate task
        asyncio.create_task(client1.listen_for_messages(reader1))

        await client1.send_message("Hello from TestClient1!")
        await asyncio.sleep(1)
        await client1.send_message("Another message from TestClient1.")
        
        # Keep client alive for a bit to receive messages
        await asyncio.sleep(5)
        await client1.close()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Client shutting down.")

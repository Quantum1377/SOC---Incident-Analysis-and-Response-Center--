
import asyncio
import logging
import ssl

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class EventBus:
    def __init__(self, host='0.0.0.0', port=9999, use_ssl=True):
        self._host = host
        self._port = port
        self._writers = []
        self.logger = logging.getLogger('EventBus')
        if use_ssl:
            self._ssl_context = self._create_ssl_context() # New: Create SSL context
        else:
            self._ssl_context = None

    def _create_ssl_context(self):
        """Creates an SSL context for the server."""
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(
            certfile="secure_storage/cert.pem",
            keyfile="secure_storage/key.pem"
        )
        return ssl_context

    async def _broadcast(self, message: str):
        """Sends a message to all connected clients."""
        self.logger.info(f"Broadcasting message: {message.strip()}")
        # Create a copy of the writers list to avoid issues if a writer is removed during iteration
        for writer in self._writers[:]:
            try:
                writer.write(message.encode())
                await writer.drain()
            except ConnectionError:
                self.logger.warning(f"Failed to send message to a client. It might be disconnected. Removing it.")
                self._writers.remove(writer)
                writer.close()
                await writer.wait_closed()


    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Callback to handle a new client connection."""
        addr = writer.get_extra_info('peername')
        self.logger.info(f"New connection from {addr}")
        self._writers.append(writer)

        try:
            while True:
                data = await reader.readline()
                if not data:
                    self.logger.info(f"Client {addr} disconnected.")
                    break
                
                self.logger.info(f"Received raw data from {addr}: {data.decode().strip()}")
                message = data.decode()
                # We broadcast the message to all clients
                await self._broadcast(message)

        except ConnectionResetError:
            self.logger.warning(f"Connection reset by client {addr}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred with client {addr}: {e}")
        finally:
            self.logger.info(f"Closing connection with {addr}")
            if writer in self._writers:
                self._writers.remove(writer)
            writer.close()
            await writer.wait_closed()
            
    async def ping_clients(self):
        """Periodically sends a ping to all clients."""
        while True:
            await asyncio.sleep(5)
            ping_message = "[EventBus] PING\n"
            await self._broadcast(ping_message)

    async def start(self):
        """Starts the event bus server."""
        server = await asyncio.start_server(
            self.handle_client,
            self._host,
            self._port,
            ssl=self._ssl_context if self._ssl_context else None # New: Pass SSL context
        )
        addr = server.sockets[0].getsockname()
        self.logger.info(f"Event bus server started on {addr}")

        # Start the ping task
        asyncio.create_task(self.ping_clients())

        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    bus = EventBus()
    try:
        asyncio.run(bus.start())
    except KeyboardInterrupt:
        logging.info("Event bus server shutting down.")

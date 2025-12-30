
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

EVENT_BUS_HOST = '127.0.0.1'
EVENT_BUS_PORT = 9999
CLIENT_NAME = 'Test-Listener'

async def listen_to_bus():
    logger = logging.getLogger(CLIENT_NAME)
    
    try:
        reader, writer = await asyncio.open_connection(EVENT_BUS_HOST, EVENT_BUS_PORT)
        logger.info(f"Connected to event bus at {EVENT_BUS_HOST}:{EVENT_BUS_PORT}")
    except ConnectionRefusedError:
        logger.error("Connection refused. Is the event bus server running?")
        return
    except Exception as e:
        logger.error(f"Error connecting to event bus: {e}")
        return

    try:
        while True:
            data = await reader.readline()
            if not data:
                logger.info("Disconnected from event bus.")
                break
            
            message = data.decode().strip()
            logger.info(f"Received from bus: {message}")

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        if 'writer' in locals() and not writer.is_closing():
            logger.info("Closing connection.")
            writer.close()
            await writer.wait_closed()

if __name__ == '__main__':
    try:
        asyncio.run(listen_to_bus())
    except KeyboardInterrupt:
        logging.info("Listener client shutting down.")

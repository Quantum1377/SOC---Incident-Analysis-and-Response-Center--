import asyncio
import json
import logging
from datetime import datetime

# Assuming event_client.py is in the parent directory
# This might need adjustment based on how the script is run.
import sys
import os
# Add project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from event_client import EventClient

# --- Configuration ---
LOG_FILE = "edr_data.log"
CLIENT_NAME = "EDR_Server_Listener"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(CLIENT_NAME)

async def process_event(message: str):
    """Parses and logs EDR data from an event bus message."""
    try:
        event = json.loads(message)
        if event.get('type') == 'EDR_DATA':
            logger.info(f"Received EDR data from agent: {event.get('source', 'Unknown Agent')}")

            # Add server-side timestamp for consistency
            event['server_timestamp'] = datetime.utcnow().isoformat()

            # Write data to a log file
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(event) + "\n")
        
        # Could add handlers for other event types here if needed

    except json.JSONDecodeError:
        logger.warning(f"Received non-JSON message: {message}")
    except Exception as e:
        logger.error(f"Error processing message: {e}")

async def main():
    logger.info("EDR Server Listener starting...")
    
    # Initialize the client
    client = EventClient(CLIENT_NAME)
    
    # Attempt to connect
    reader, writer = await client.connect()

    if not (reader and writer):
        logger.error("Failed to connect to the event bus. Shutting down.")
        return

    logger.info("Connected to event bus. Listening for EDR data...")

    try:
        while True:
            data = await reader.readline()
            if not data:
                logger.warning("Disconnected from event bus. Attempting to reconnect...")
                # Simple reconnect loop
                while not (reader and writer):
                    await asyncio.sleep(5)
                    reader, writer = await client.connect()
                logger.info("Reconnected to event bus.")
                continue
            
            message = data.decode().strip()
            await process_event(message)

    except asyncio.CancelledError:
        logger.info("Listener task cancelled.")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the listener loop: {e}")
    finally:
        logger.info("Closing connection.")
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("EDR Server Listener stopped by user.")

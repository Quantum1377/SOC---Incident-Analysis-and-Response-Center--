import asyncio
import time
import logging
import json

EVENT_BUS_HOST = '127.0.0.1'
EVENT_BUS_PORT = 9999
LOG_FILE_TO_WATCH = 'test_auth.log'
CLIENT_NAME = 'LogProducer'

async def tail_log_and_publish():
    """Tails a log file and publishes new lines to the event bus."""
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
        with open(LOG_FILE_TO_WATCH, 'r') as f:
            # Go to the end of the file
            f.seek(0, 2)
            logger.info(f"Tailing log file: {LOG_FILE_TO_WATCH}")

            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.5)  # Sleep briefly if no new line
                    continue

                line = line.strip()
                if line:
                    logger.info(f"New log entry found: {line}")
                    # Prepare the event message
                    event = {
                        "source": CLIENT_NAME,
                        "type": "LOG_ENTRY",
                        "payload": line
                    }
                    message = json.dumps(event) + "\n"
                    writer.write(message.encode())
                    await writer.drain()
                    logger.info("Published log entry to event bus.")

    except FileNotFoundError:
        logger.error(f"Log file not found: {LOG_FILE_TO_WATCH}. Please create it.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        if 'writer' in locals() and not writer.is_closing():
            logger.info("Closing connection to event bus.")
            writer.close()
            await writer.wait_closed()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Ensure the log file exists before starting
    with open(LOG_FILE_TO_WATCH, 'a'):
        pass
        
    try:
        asyncio.run(tail_log_and_publish())
    except KeyboardInterrupt:
        logging.info("Log producer shutting down.")
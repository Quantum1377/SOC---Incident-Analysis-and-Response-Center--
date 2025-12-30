from fastapi import FastAPI, Request
import uvicorn
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()

# Define the log file path
LOG_FILE = "edr_data.log"

@app.post("/ingest")
async def ingest_data(request: Request):
    """Receives EDR data from agents and logs it."""
    try:
        data = await request.json()
        logging.info(f"Received data from agent: {data.get('agent_id', 'Unknown Agent')}")

        # Add server-side timestamp for consistency
        data['server_timestamp'] = datetime.utcnow().isoformat()

        # Write data to a log file
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(data) + "\n")

        return {"message": "Data ingested successfully"}
    except Exception as e:
        logging.error(f"Error ingesting data: {e}")
        return {"message": f"Error: {e}"}, 500

if __name__ == "__main__":
    logging.info(f"EDR Server starting. Data will be logged to {LOG_FILE}")
    uvicorn.run(app, host="0.0.0.0", port=8000)

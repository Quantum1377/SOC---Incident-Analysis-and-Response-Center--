import os
import asyncio
import json
import logging
from openai import OpenAI
from collections import deque

# Add project root to the Python path to allow imports from other modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from event_client import EventClient

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AIOperator")

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_BASE = "https://api.deepseek.com/v1"
EDR_LOG_FILE = "logs/edr_data.log"

class AIOperator:
    def __init__(self):
        if not DEEPSEEK_API_KEY:
            logger.warning("DEEPSEEK_API_KEY environment variable not set. AI Operator will not be able to generate plans or chat.")
            self.ai_client = None
        else:
            self.ai_client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_API_BASE)
            logger.info("AI Client initialized for Deepseek.")

    async def send_event(self, writer: asyncio.StreamWriter, event_type: str, payload: dict):
        event = {"source": "AIOperator", "type": event_type, "payload": payload}
        message = json.dumps(event) + "\n"
        if writer and not writer.is_closing():
            logger.info(f"Publishing event: {event_type}")
            writer.write(message.encode())
            await writer.drain()
        else:
            logger.error("Cannot send event: Writer is closed or invalid.")

    async def main_loop(self):
        listener_client = EventClient("AIOperatorListener")
        while True:
            reader, writer = await listener_client.connect()
            if not reader or not writer:
                logger.error("Could not connect to event bus. Retrying in 10 seconds...")
                await asyncio.sleep(10)
                continue
            logger.info("AI Operator is connected to the event bus.")
            try:
                while True:
                    data = await reader.readline()
                    if not data:
                        logger.warning("Disconnected from event bus. Will attempt to reconnect.")
                        break
                    message = data.decode().strip()
                    asyncio.create_task(self.handle_event(message, writer))
            except asyncio.CancelledError:
                logger.info("Main loop cancelled.")
                break
            except Exception as e:
                logger.error(f"Error in listener loop: {e}. Reconnecting...")
            finally:
                await listener_client.close()
                await asyncio.sleep(5)

    async def handle_event(self, message: str, writer: asyncio.StreamWriter):
        try:
            event = json.loads(message)
            event_type = event.get("type")

            if event_type in ["ssh_brute_force_detected", "web_attack_detected", "port_scan_detected", "dos_attack_detected"]:
                logger.info(f"Threat detected: {event_type}. Generating response plan.")
                incident_id = f"{event_type}-{event['payload'].get('source_ip', 'unknown')}-{int(asyncio.get_running_loop().time())}"
                plan = await self.generate_plan(event)
                if plan:
                    logger.info(f"Plan generated for incident {incident_id}: {plan}")
                    await self.send_event(writer, "ai_plan_generated", {"incident_id": incident_id, "original_event": event, "plan": plan})
                else:
                    logger.error(f"Failed to generate a plan for incident {incident_id}.")
            
            elif event_type == "chat_message_from_user":
                logger.info(f"Chat message received from user. Processing...")
                await self.handle_chat_message(event.get("payload", {}), writer)

        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.error(f"Error handling event: {e}\nMessage: {message}")

    async def handle_chat_message(self, payload: dict, writer: asyncio.StreamWriter):
        user_question = payload.get("question")
        if not user_question:
            return

        if not self.ai_client:
            await self.send_event(writer, "ai_chat_response", {"text": "I can't answer questions right now. The AI client is not configured (DEEPSEEK_API_KEY is likely missing)."})
            return

        # Get context from EDR logs
        context = "No EDR data available."
        try:
            if os.path.exists(EDR_LOG_FILE):
                with open(EDR_LOG_FILE, 'r') as f:
                    # Read the last N lines for context
                    last_lines = deque(f, 30)
                context = "\n".join(last_lines)
        except Exception as e:
            logger.error(f"Could not read EDR log file for context: {e}")
            context = f"Error reading log file: {e}"

        prompt = f"""
        You are a helpful SOC assistant integrated into a command center dashboard.
        Your purpose is to answer questions from a system administrator about the state of their network nodes.
        Use the provided "Live EDR Data" to answer the user's question. The data is a series of JSON objects, each representing a snapshot from an agent.
        Be concise and clear in your answers. If the data is not present to answer the question, say so.

        **Live EDR Data (last 30 entries):**
        ```json
        {context}
        ```

        **User's Question:**
        "{user_question}"
        """

        try:
            response = await asyncio.to_thread(
                self.ai_client.chat.completions.create,
                model="deepseek-chat",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.3,
            )
            ai_response = response.choices[0].message.content
        except Exception as e:
            logger.error(f"Failed to get a valid response from AI for chat: {e}")
            ai_response = "I encountered an error while trying to process your question."

        await self.send_event(writer, "ai_chat_response", {"text": ai_response})

    async def generate_plan(self, event: dict) -> list | None:
        if not self.ai_client:
            logger.warning("Cannot generate plan: AI client not initialized.")
            return [{"action": "create_ticket", "parameters": {"title": "AI Operator Misconfigured", "description": "DEEPSEEK_API_KEY is not set.", "priority": "high"}}]

        prompt = f"""
        You are an automated Security Operations Center (SOC) decision engine.
        A security threat has been detected in our system. Your task is to generate a concise, step-by-step mitigation plan.
        **Detected Threat:**
        - Event Type: {event.get('type')}
        - Source: {event.get('source')}
        - Details: {json.dumps(event.get('payload'))}
        **Your Capabilities:**
        You can only use the following actions: `firewall_block(ip, duration_seconds)`, `firewall_unblock(ip)`, `analyze_traffic(interface, filter)`, `isolate_node(node_id)`, `notify(channel, subject, message)`, `create_ticket(title, description, priority)`.
        **Your Response:**
        Provide the response as a valid JSON object with a single key "plan" which is an array of objects. Each object must have an "action" and "parameters" key.
        The plan should be logical and aimed at mitigating the specific threat.
        Example: {{"plan": [{{"action": "firewall_block", "parameters": {{"ip": "1.2.3.4"}}}}]}}
        Now, generate the plan for the detected threat.
        """

        try:
            response = await asyncio.to_thread(
                self.ai_client.chat.completions.create,
                model="deepseek-reasoner",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            response_json = json.loads(response.choices[0].message.content)
            if "plan" in response_json and isinstance(response_json["plan"], list):
                return response_json["plan"]
            else:
                logger.error(f"AI response did not contain a valid 'plan' array: {response.choices[0].message.content}")
                return None
        except Exception as e:
            logger.error(f"Failed to get a valid plan from AI: {e}")
            return None

if __name__ == "__main__":
    op = AIOperator()
    try:
        asyncio.run(op.main_loop())
    except KeyboardInterrupt:
        logger.info("AI Operator shutting down.")


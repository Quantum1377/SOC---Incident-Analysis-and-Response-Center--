import asyncio
import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox
import threading
import logging
import ssl
import bcrypt
import json
import os
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class EventClient:
    def __init__(self, name, host='127.0.0.1', port=9999, app=None):
        self.name = name
        self._host = host
        self._port = port
        self.logger = logging.getLogger(f'EventClient-{name}')
        self.app = app # Reference to the main DashboardApp
        self._writer = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def _create_ssl_context(self):
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(cafile="secure_storage/cert.pem")
        return ssl_context

    def start_client(self):
        asyncio.run_coroutine_threadsafe(self._run(), self._loop)

    async def _run(self):
        try:
            ssl_context = self._create_ssl_context()
            reader, writer = await asyncio.open_connection(self._host, self._port, ssl=ssl_context)
            self._writer = writer
            self.logger.info("Dashboard UI connected to event bus.")
            if self.app:
                self.app.display_message("System", "Connected to Event Bus...")
            await self.listen_for_messages(reader)
        except ConnectionRefusedError:
            self.logger.error(f"Connection refused. Is the event bus server running?")
            if self.app:
                self.app.display_message("System", "Connection Refused. Start event_bus.py.", "error")
        except Exception as e:
            self.logger.error(f"Error connecting dashboard client: {e}")

    async def send_message(self, message: str):
        if self._writer and not self._writer.is_closing():
            full_message = f"[{self.name}] {message}\n"
            self.logger.info(f"Sending: {full_message.strip()}")
            self._writer.write(full_message.encode())
            await self._writer.drain()
        else:
            self.logger.warning("Dashboard UI not connected. Cannot send message.")

    def send_message_threadsafe(self, message: str):
        asyncio.run_coroutine_threadsafe(self.send_message(message), self._loop)

    async def listen_for_messages(self, reader: asyncio.StreamReader):
        try:
            while True:
                data = await reader.readline()
                if not data:
                    self.logger.info("Disconnected from event bus.")
                    if self.app:
                        self.app.display_message("System", "Disconnected from Event Bus.", "error")
                    break
                
                message = data.decode().strip()
                try:
                    event = json.loads(message)
                    event_type = event.get("type", "unknown")
                    
                    if event_type == "ai_plan_generated":
                        if self.app:
                            self.app.display_ai_plan(event.get("payload", {}))
                    elif event_type == "ai_chat_response":
                        if self.app:
                            self.app.display_chat_message("Assistant", event.get("payload", {}).get("text", "No response text found."))
                    else:
                        source = event.get('source', 'unknown')
                        payload_preview = json.dumps(event.get('payload', ''))
                        formatted_msg = f"[{source}|{event_type}] {payload_preview}"
                        if self.app:
                            self.app.display_message("Event", formatted_msg)
                except json.JSONDecodeError:
                    if self.app:
                        self.app.display_message("Raw", message)

        except Exception as e:
            self.logger.error(f"Error listening for messages: {e}")

    def close(self):
        if self._writer and not self._writer.is_closing():
            self._loop.call_soon_threadsafe(self._writer.close)
        self._loop.call_soon_threadsafe(self._loop.stop)


DASHBOARD_CONFIG_FILE = "secure_storage/dashboard_config.json"

def _check_and_set_password(root):
    if not os.path.exists(DASHBOARD_CONFIG_FILE):
        messagebox.showinfo("Setup Password", "First time use: Please set a password for the dashboard.")
        while True:
            password = simpledialog.askstring("Set Password", "Enter new password:", show='*')
            if not password: return False
            confirm_password = simpledialog.askstring("Set Password", "Confirm new password:", show='*')
            if password == confirm_password:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                with open(DASHBOARD_CONFIG_FILE, 'w') as f:
                    json.dump({"hashed_password": hashed_password, "configured": True}, f)
                messagebox.showinfo("Password Set", "Password set successfully!")
                return True
            else:
                messagebox.showerror("Error", "Passwords do not match. Please try again.")
    else:
        with open(DASHBOARD_CONFIG_FILE, 'r') as f:
            config = json.load(f)
        hashed_password = config["hashed_password"].encode('utf-8')
        while True:
            password = simpledialog.askstring("Enter Password", "Enter dashboard password:", show='*')
            if not password: return False
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                messagebox.showinfo("Access Granted", "Welcome to the Dashboard!")
                return True
            else:
                messagebox.showerror("Error", "Incorrect password. Please try again.")

class DashboardApp:
    def __init__(self, root):
        self.root = root
        root.title("SOC AI Command Center")
        root.geometry("1200x900") # Increased height for chat
        self.plan_details = {} # Store for plan details

        # --- Main Layout Paned Window (Vertical) ---
        main_pane = tk.PanedWindow(root, orient=tk.VERTICAL, sashrelief=tk.RAISED)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Top Pane for AI Plans and Logs (Horizontal) ---
        top_pane = tk.PanedWindow(main_pane, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        main_pane.add(top_pane, height=400)

        # AI Plans Frame
        ai_frame = ttk.LabelFrame(top_pane, text="AI Generated Response Plans")
        top_pane.add(ai_frame, width=600)
        
        # Treeview for plan list
        self.ai_plan_display = ttk.Treeview(ai_frame, columns=("Timestamp", "Incident", "Source IP"), show="headings")
        self.ai_plan_display.heading("Timestamp", text="Timestamp")
        self.ai_plan_display.heading("Incident", text="Incident")
        self.ai_plan_display.heading("Source IP", text="Source IP")
        self.ai_plan_display.column("Timestamp", width=150)
        self.ai_plan_display.column("Incident", width=250)
        self.ai_plan_display.column("Source IP", width=120)
        self.ai_plan_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ai_plan_display.bind("<<TreeviewSelect>>", self.on_plan_select)

        # Plan Detail View
        plan_detail_frame = ttk.LabelFrame(top_pane, text="Plan Details")
        self.plan_detail_display = scrolledtext.ScrolledText(plan_detail_frame, state='disabled', wrap=tk.WORD, height=10)
        self.plan_detail_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        top_pane.add(plan_detail_frame)

        # --- Middle Pane for Raw Event Log ---
        log_frame = ttk.LabelFrame(main_pane, text="Raw Event Stream")
        main_pane.add(log_frame, height=250)
        self.log_display = scrolledtext.ScrolledText(log_frame, state='normal', wrap=tk.WORD, height=15)
        self.log_display.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # --- Bottom Pane for AI Chat ---
        chat_frame = ttk.LabelFrame(main_pane, text="AI Chat Assistant")
        main_pane.add(chat_frame)
        
        self.chat_history = scrolledtext.ScrolledText(chat_frame, state='disabled', wrap=tk.WORD, height=10)
        self.chat_history.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.chat_input = ttk.Entry(chat_frame, font=("Arial", 10))
        self.chat_input.pack(fill=tk.X, padx=5, pady=(0, 5))
        self.chat_input.bind("<Return>", self.send_chat_message)
        self.display_chat_message("Assistant", "Type '/chat [your question]' to talk to the AI about your system's nodes.")


        # Initialize and start the event client
        self.client = EventClient("DashboardUI", app=self)
        self.client.start_client()
        
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_plan_select(self, event):
        """Called when a user selects a plan in the treeview."""
        selected_item = self.ai_plan_display.focus()
        if not selected_item: return
        details = self.plan_details.get(selected_item, "Plan details not found.")
        self.plan_detail_display.config(state='normal')
        self.plan_detail_display.delete('1.0', tk.END)
        self.plan_detail_display.insert(tk.END, details)
        self.plan_detail_display.config(state='disabled')

    def display_message(self, source, message, level="info"):
        """Thread-safe method to display a message in the log viewer."""
        def _display():
            timestamp = datetime.now().strftime("%H:%M:%S")
            full_message = f"{timestamp} [{source}]: {message}\n"
            self.log_display.insert(tk.END, full_message)
            self.log_display.see(tk.END)
        if self.root.winfo_exists():
            self.root.after(0, _display)

    def display_ai_plan(self, payload):
        """Thread-safe method to display a new AI plan."""
        def _display():
            incident_id = payload.get("incident_id", "N/A")
            original_event = payload.get("original_event", {})
            plan = payload.get("plan", [])
            event_payload = original_event.get("payload", {})
            threat_type = original_event.get("type", "N/A")
            source_ip = event_payload.get("source_ip", "N/A")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            item_id = self.ai_plan_display.insert("", "end", values=(timestamp, threat_type, source_ip))
            
            detail_text = f"Incident ID: {incident_id}\nThreat Type: {threat_type}\nSource IP: {source_ip}\n"
            detail_text += "-"*20 + "\nAI Generated Plan:\n"
            for i, step in enumerate(plan, 1):
                action = step.get("action")
                params = json.dumps(step.get("parameters"))
                detail_text += f"  Step {i}: {action}\n    Params: {params}\n"
            self.plan_details[item_id] = detail_text
            self.display_message("AIOperator", f"New plan generated for {threat_type} from {source_ip}.", "info")
        if self.root.winfo_exists():
            self.root.after(0, _display)
    
    def display_chat_message(self, source, text):
        """Thread-safe method to display a message in the chat history."""
        def _display():
            self.chat_history.config(state='normal')
            self.chat_history.insert(tk.END, f"[{source}]: {text}\n\n")
            self.chat_history.config(state='disabled')
            self.chat_history.see(tk.END)
        if self.root.winfo_exists():
            self.root.after(0, _display)

    def send_chat_message(self, event):
        """Handles sending a user's chat message."""
        user_input = self.chat_input.get().strip()
        if not user_input:
            return

        self.chat_input.delete(0, tk.END)
        self.display_chat_message("You", user_input)

        if user_input.lower().startswith("/chat "):
            question = user_input[6:].strip()
            if not question:
                self.display_chat_message("Assistant", "Please provide a question after '/chat'.")
                return

            chat_event = {
                "type": "chat_message_from_user",
                "payload": {
                    "question": question,
                    "timestamp": datetime.now().isoformat()
                }
            }
            self.client.send_message_threadsafe(json.dumps(chat_event))
            self.display_chat_message("Assistant", "Thinking...")
        else:
            self.display_chat_message("Assistant", "Invalid command. Please start your message with '/chat'.")


    def on_closing(self):
        self.client.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw() # Hide the main window initially

    if _check_and_set_password(root):
        root.deiconify() # Show the main window if password is correct
        app = DashboardApp(root)
        root.mainloop()
    else:
        root.destroy()
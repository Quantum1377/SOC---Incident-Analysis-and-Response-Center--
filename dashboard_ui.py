import asyncio
import tkinter as tk
from tkinter import scrolledtext
import threading
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class EventClient:
    def __init__(self, name, host='127.0.0.1', port=9999, text_widget=None):
        self.name = name
        self._host = host
        self._port = port
        self.logger = logging.getLogger(f'EventClient-{name}')
        self.text_widget = text_widget
        self._writer = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def start_client(self):
        asyncio.run_coroutine_threadsafe(self._run(), self._loop)

    async def _run(self):
        try:
            reader, writer = await asyncio.open_connection(self._host, self._port)
            self._writer = writer
            self.logger.info(f"Dashboard UI connected to event bus.")
            if self.text_widget:
                self.text_widget.insert(tk.END, "Connected to Event Bus...\n")
            
            await self.listen_for_messages(reader)
        except ConnectionRefusedError:
            self.logger.error(f"Connection refused. Is the event bus server running on {self._host}:{self._port}?")
            if self.text_widget:
                self.text_widget.insert(tk.END, "Connection Refused. Start event_bus.py.\n")
        except Exception as e:
            self.logger.error(f"Error connecting dashboard client: {e}")

    async def send_message(self, message: str):
        if self._writer:
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
                    if self.text_widget:
                        self.text_widget.insert(tk.END, "Disconnected from Event Bus.\n")
                    break
                message = data.decode().strip()
                if self.text_widget:
                    # Safely update Tkinter widget from another thread
                    self.text_widget.insert(tk.END, message + "\n")
                    self.text_widget.see(tk.END) # Auto-scroll
        except Exception as e:
            self.logger.error(f"Error listening for messages: {e}")

    def close(self):
        if self._writer:
            self._loop.call_soon_threadsafe(self._writer.close)
        self._loop.call_soon_threadsafe(self._loop.stop)


class DashboardApp:
    def __init__(self, root):
        self.root = root
        root.title("SOC Dashboard")
        root.geometry("800x600")

        # Main frame
        main_frame = tk.Frame(root)
        main_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Event log display
        log_frame = tk.LabelFrame(main_frame, text="Event Stream")
        log_frame.pack(pady=5, fill="both", expand=True)

        self.log_display = scrolledtext.ScrolledText(log_frame, state='normal', wrap=tk.WORD, height=15)
        self.log_display.pack(padx=5, pady=5, fill="both", expand=True)

        # Control panel
        control_frame = tk.LabelFrame(main_frame, text="System Control")
        control_frame.pack(pady=5, fill="x")
        
        self.client = EventClient("DashboardUI", text_widget=self.log_display)
        self.client.start_client()

        # Example button to send a command
        self.test_button = tk.Button(control_frame, text="Send Test Message", command=self.send_test_message)
        self.test_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def send_test_message(self):
        self.client.send_message_threadsafe("MAINTENANCE:machine-123")

    def on_closing(self):
        self.client.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = DashboardApp(root)
    root.mainloop()
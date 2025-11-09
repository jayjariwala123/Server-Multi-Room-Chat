#!/usr/bin/env python3
"""
chat_client_gui.py
Tkinter GUI client for the TCP chat server (connects directly to chat_with_sniffer.py).
Author: Jay Jariwala
"""

import os
# silence macOS Tk deprecation warning
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

import socket
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext, messagebox

PORT = 5555
RECV_BUFFER = 4096

class ChatClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Real-Time Chat Client")
        self.master.geometry("560x520")
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

        # connection
        self.sock = None
        self.recv_thread = None
        self.running = False

        # queue for incoming messages (thread-safe)
        self.msg_queue = queue.Queue()

        # --- Layout ---
        top_frame = tk.Frame(master)
        tk.Label(top_frame, text="Server IP:").grid(row=0, column=0, padx=4, pady=6, sticky="e")
        self.ip_entry = tk.Entry(top_frame, width=18)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=4, pady=6)

        tk.Label(top_frame, text="Username:").grid(row=0, column=2, padx=4, pady=6, sticky="e")
        self.username_entry = tk.Entry(top_frame, width=18)
        self.username_entry.grid(row=0, column=3, padx=4, pady=6)

        self.connect_btn = tk.Button(top_frame, text="Connect", width=12, command=self.connect_to_server)
        self.connect_btn.grid(row=0, column=4, padx=6)
        self.disconnect_btn = tk.Button(top_frame, text="Disconnect", width=12, state="disabled", command=self.disconnect)
        self.disconnect_btn.grid(row=0, column=5, padx=6)
        top_frame.pack(pady=8, padx=8, fill="x")

        # Chat area
        self.chat_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, state="disabled", height=24)
        self.chat_area.pack(padx=10, pady=(4, 0), fill="both", expand=True)

        # send controls
        bottom_frame = tk.Frame(master)
        self.message_entry = tk.Entry(bottom_frame, width=58)
        self.message_entry.pack(side=tk.LEFT, padx=(4,6), pady=8, expand=True, fill="x")
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        tk.Button(bottom_frame, text="Send", width=10, command=self.send_message).pack(side=tk.LEFT, padx=(0,6))
        tk.Button(bottom_frame, text="Exit", width=10, command=self.on_close).pack(side=tk.LEFT)
        bottom_frame.pack(padx=10, pady=(0,10), fill="x")

        # periodic check for messages from receiver thread
        self.master.after(100, self.process_incoming_messages)

    def connect_to_server(self):
        server_ip = self.ip_entry.get().strip()
        username = self.username_entry.get().strip()
        if not server_ip or not username:
            messagebox.showwarning("Input required", "Please enter both Server IP and Username.")
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((server_ip, PORT))
            # Send username right away to match your server expectation
            self.sock.send(username.encode())

            self.running = True
            self.recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.recv_thread.start()

            self.connect_btn.config(state="disabled")
            self.disconnect_btn.config(state="normal")
            self.append_text(f"[INFO] Connected to {server_ip}:{PORT} as {username}")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server:\n{e}")
            if self.sock:
                try: self.sock.close()
                except: pass
                self.sock = None

    def receive_loop(self):
        """Runs in background thread — receives data and pushes to queue."""
        try:
            while self.running:
                data = self.sock.recv(RECV_BUFFER)
                if not data:
                    # server closed connection
                    self.msg_queue.put("[SYSTEM] Disconnected from server.")
                    break
                # decode and enqueue
                try:
                    text = data.decode(errors="replace")
                except:
                    text = repr(data)
                self.msg_queue.put(text)
        except Exception as e:
            # push exception into UI queue
            self.msg_queue.put(f"[ERROR] Connection error: {e}")
        finally:
            self.running = False
            try:
                if self.sock:
                    self.sock.close()
            except:
                pass
            self.sock = None
            self.msg_queue.put("[SYSTEM] Receiver stopped.")

    def process_incoming_messages(self):
        """Called periodically on main thread to update UI from queue."""
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self.append_text(msg)
        except queue.Empty:
            pass
        self.master.after(100, self.process_incoming_messages)

    def append_text(self, text):
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, text + "\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state="disabled")

    def send_message(self):
        if not self.sock:
            messagebox.showwarning("Not connected", "Connect to a server first.")
            return
        msg = self.message_entry.get().strip()
        if not msg:
            return
        try:
            self.sock.send(msg.encode())
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")

    def disconnect(self):
        self.running = False
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
        except:
            pass
        self.sock = None
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self.append_text("[INFO] Disconnected.")

    def on_close(self):
        # graceful close
        self.disconnect()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()

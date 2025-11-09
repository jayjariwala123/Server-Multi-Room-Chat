import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import os

# Fix macOS warning
os.environ["TK_SILENCE_DEPRECATION"] = "1"

# ---------- CLIENT LOGIC ----------
class ChatClient:
    def __init__(self, gui):
        self.gui = gui
        self.client_socket = None
        self.running = False

    def connect(self, ip, port, username):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, port))
            self.running = True
            self.client_socket.send(username.encode('utf-8'))
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.gui.show_message("✅ Connected to the server.")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect: {e}")

    def receive_messages(self):
        while self.running:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                self.gui.show_message(message)
            except:
                self.running = False
                break

    def send_message(self, message):
        if self.client_socket and self.running:
            try:
                self.client_socket.send(message.encode('utf-8'))
            except:
                self.gui.show_message("⚠️ Error sending message.")
        else:
            messagebox.showwarning("Not Connected", "Please connect to the server first.")

    def disconnect(self):
        self.running = False
        if self.client_socket:
            self.client_socket.close()
        self.gui.show_message("❌ Disconnected from the server.")


# ---------- GUI PART ----------
class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Chat Client")
        self.root.geometry("600x500")
        self.root.configure(bg="#1e1e1e")

        self.client = ChatClient(self)

        # Username
        tk.Label(root, text="Username:", fg="white", bg="#1e1e1e").pack(pady=(10,0))
        self.username_entry = tk.Entry(root, width=25)
        self.username_entry.pack()

        # Server IP & Port
        tk.Label(root, text="Server IP:", fg="white", bg="#1e1e1e").pack(pady=(5,0))
        self.ip_entry = tk.Entry(root, width=25)
        self.ip_entry.insert(0, "127.0.0.1")  # default localhost
        self.ip_entry.pack()

        tk.Label(root, text="Port:", fg="white", bg="#1e1e1e").pack(pady=(5,0))
        self.port_entry = tk.Entry(root, width=25)
        self.port_entry.insert(0, "5555")
        self.port_entry.pack()

        # Connect Button
        tk.Button(root, text="Connect", bg="#0078D7", fg="white", command=self.connect_server).pack(pady=10)

        # Chat Display
        self.chat_box = scrolledtext.ScrolledText(root, width=70, height=20, bg="#252526", fg="white", wrap=tk.WORD)
        self.chat_box.pack(padx=10, pady=10)
        self.chat_box.config(state=tk.DISABLED)

        # Message Entry + Send
        frame = tk.Frame(root, bg="#1e1e1e")
        frame.pack()
        self.msg_entry = tk.Entry(frame, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Send", bg="#0078D7", fg="white", command=self.send_message).pack(side=tk.LEFT)

    def show_message(self, message):
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, f"{message}\n")
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.see(tk.END)

    def connect_server(self):
        username = self.username_entry.get()
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())

        if username:
            self.client.connect(ip, port, username)
        else:
            messagebox.showwarning("Missing Info", "Please enter a username before connecting.")

    def send_message(self):
        msg = self.msg_entry.get()
        if msg:
            self.client.send_message(msg)
            self.msg_entry.delete(0, tk.END)


# ---------- MAIN ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()

"""
Project: Real-Time Chat Communication with Integrated Network Packet Sniffer
Author: Jay Jariwala
Description:
    Multi-client TCP chat system with integrated packet sniffer.
    Demonstrates end-to-end data communication across OSI layers.
"""

import socket
import threading
from scapy.all import sniff, IP, TCP
from colorama import Fore, Style, init

init(autoreset=True)

# ==============================
# 🔹 CONFIGURATION
# ==============================
HOST = '0.0.0.0'
PORT = 5555
clients = []
usernames = {}

# ==============================
# 🔹 PACKET SNIFFER FUNCTIONALITY
# ==============================

def packet_callback(packet):
    """Display a short summary of each sniffed TCP packet."""
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        print(Fore.YELLOW + f"[SNIFFER] TCP Packet | {src} → {dst}" + Style.RESET_ALL)

def start_sniffer():
    """Start the sniffer in a background thread."""
    print(Fore.CYAN + "[SNIFFER] Capturing TCP packets on port 5555...\n" + Style.RESET_ALL)
    sniff(filter=f"tcp port {PORT}", prn=packet_callback, store=False)


# ==============================
# 🔹 SERVER FUNCTIONALITY
# ==============================

def broadcast(message, connection):
    """Send a message to all connected clients except the sender."""
    for client in clients:
        if client != connection:
            try:
                client.send(message)
            except:
                clients.remove(client)

def handle_client(conn, addr):
    """Handle incoming messages from a connected client."""
    print(Fore.GREEN + f"[SERVER] Connected with {addr}" + Style.RESET_ALL)
    conn.send("Enter your username: ".encode())
    username = conn.recv(1024).decode().strip()
    usernames[conn] = username

    welcome = f"{username} joined the chat!"
    print(Fore.MAGENTA + f"[SERVER] {welcome}" + Style.RESET_ALL)
    broadcast(f"{welcome}".encode(), conn)

    while True:
        try:
            msg = conn.recv(1024)
            if not msg:
                break
            decoded = msg.decode()
            print(Fore.BLUE + f"[{username}] {decoded}" + Style.RESET_ALL)
            broadcast(f"{username}: {decoded}".encode(), conn)
        except:
            break

    print(Fore.RED + f"[SERVER] {username} disconnected." + Style.RESET_ALL)
    clients.remove(conn)
    conn.close()
    broadcast(f"{username} left the chat.".encode(), conn)

def start_server():
    """Launch the chat server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(Fore.CYAN + f"[SERVER] Running on {HOST}:{PORT}" + Style.RESET_ALL)
    print(Fore.CYAN + "[SERVER] Waiting for clients...\n" + Style.RESET_ALL)

    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


# ==============================
# 🔹 CLIENT FUNCTIONALITY
# ==============================

def start_client():
    """Connect to the chat server."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = input("Enter server IP (default=127.0.0.1): ") or "127.0.0.1"
    client.connect((server_ip, PORT))

    def receive_messages():
        while True:
            try:
                msg = client.recv(1024).decode()
                if not msg:
                    break
                print(Fore.LIGHTGREEN_EX + f"\n{msg}" + Style.RESET_ALL)
            except:
                print(Fore.RED + "[CLIENT] Disconnected from server." + Style.RESET_ALL)
                break

    threading.Thread(target=receive_messages, daemon=True).start()

    username = input("Enter your username: ")
    client.send(username.encode())
    print(Fore.CYAN + "\n=== Connected! Type messages below (type 'exit' to quit) ===" + Style.RESET_ALL)

    while True:
        message = input()
        if message.lower() == 'exit':
            client.close()
            print(Fore.YELLOW + "You left the chat." + Style.RESET_ALL)
            break
        client.send(message.encode())


# ==============================
# 🔹 MAIN PROGRAM
# ==============================

if __name__ == "__main__":
    print(Fore.CYAN + "Select Mode:" + Style.RESET_ALL)
    print("1. Start Server + Packet Sniffer")
    print("2. Start Client")
    choice = input("Enter choice (1/2): ")

    if choice == '1':
        threading.Thread(target=start_sniffer, daemon=True).start()
        start_server()

    elif choice == '2':
        start_client()

    else:
        print("Invalid choice. Exiting.")

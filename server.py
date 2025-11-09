"""
Project: Real-Time Multi-Room Chat with Integrated Packet Sniffer (Web Version)
Author: Jay Jariwala & Simran Nayak
"""

from flask import Flask, render_template, request
from flask_socketio import SocketIO, join_room, leave_room, send
from threading import Thread
from scapy.all import sniff, IP, TCP
from colorama import Fore, Style, init

init(autoreset=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jayjariwala'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store usernames and their rooms
users = {}

# ==========================
# 🔹 PACKET SNIFFER
# ==========================

def packet_callback(packet):
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        print(Fore.YELLOW + f"[SNIFFER] TCP Packet | {src} → {dst}" + Style.RESET_ALL)

def start_sniffer():
    print(Fore.CYAN + "[SNIFFER] Capturing TCP packets on port 5555...\n" + Style.RESET_ALL)
    sniff(filter="tcp port 5555", prn=packet_callback, store=False)


# ==========================
# 🔹 SOCKET EVENTS
# ==========================

@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    users[request.sid] = {'username': username, 'room': room}
    send(f"🟢 {username} joined {room}", to=room)
    print(Fore.GREEN + f"[JOIN] {username} joined {room}" + Style.RESET_ALL)

@socketio.on('message')
def handle_message(data):
    msg = data['msg']
    sid = request.sid
    if sid in users:
        username = users[sid]['username']
        room = users[sid]['room']
        full_msg = f"{username}: {msg}"
        send(full_msg, to=room)
        print(Fore.BLUE + f"[{room}] {full_msg}" + Style.RESET_ALL)

@socketio.on('leave')
def handle_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    send(f"🔴 {username} left {room}", to=room)
    print(Fore.RED + f"[LEAVE] {username} left {room}" + Style.RESET_ALL)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in users:
        username = users[sid]['username']
        room = users[sid]['room']
        send(f"🔴 {username} disconnected.", to=room)
        print(Fore.RED + f"[DISCONNECT] {username} from {room}" + Style.RESET_ALL)
        del users[sid]

@app.route('/')
def index():
    return render_template('index.html')


# ==========================
# 🔹 MAIN
# ==========================

if __name__ == '__main__':
    sniffer_thread = Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    print(Fore.CYAN + "[SERVER] Running Flask-SocketIO on http://127.0.0.1:5555" + Style.RESET_ALL)
    socketio.run(app, host='0.0.0.0', port=5555)

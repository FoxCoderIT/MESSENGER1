import socket
import threading
import json
import re



SERVER_HOST = '192.168.1.229'
SERVER_PORT = 8080
clients = {}
users = {}

USERS_FILE = "users.json"

def load_users():
    try:
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users():
    with open(USERS_FILE, "w") as file:
        json.dump(users, file)

def broadcast(message, client_socket):
    for client in clients.values():
        if client != client_socket:
            try:
                client.send(message)
            except:
                remove_client(client)

def send_user_list():
    user_list = json.dumps({"type": "user_list", "users": list(clients.keys())})
    for client in clients.values():
        client.send(user_list.encode('utf-8'))

def remove_client(client_socket):
    for username, sock in clients.items():
        if sock == client_socket:
            print(f"Client {username} disconnected")
            del clients[username]
            send_user_list()
            break

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                message_data = json.loads(message)
                if message_data["type"] == "login":
                    handle_login(client_socket, message_data)
                elif message_data["type"] == "register":
                    handle_register(client_socket, message_data)
                elif message_data["type"] == "change_password":
                    handle_change_password(client_socket, message_data)
                elif message_data["type"] == "message":
                    handle_message(client_socket, message_data)
        except:
            remove_client(client_socket)
            client_socket.close()
            break

def handle_login(client_socket, data):
    username = data["username"]
    password = data["password"]
    if username in users and users[username] == password:
        clients[username] = client_socket
        client_socket.send(json.dumps({"type": "login", "status": "success"}).encode('utf-8'))
        send_user_list()
    else:
        client_socket.send(json.dumps({"type": "login", "status": "failed"}).encode('utf-8'))

# Password validation function
def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    return True, ""

def handle_register(client_socket, data):
    username = data["username"]
    password = data["password"]
    if not username or not password:
        client_socket.send(json.dumps(
            {"type": "register", "status": "failed", "message": "Username and password cannot be empty"}).encode('utf-8'))
    elif username in users:
        client_socket.send(
            json.dumps({"type": "register", "status": "failed", "message": "Username already exists"}).encode('utf-8'))
    else:
        valid, message = is_valid_password(password)
        if not valid:
            client_socket.send(json.dumps({"type": "register", "status": "failed", "message": message}).encode('utf-8'))
        else:
            users[username] = password
            save_users()
            client_socket.send(json.dumps({"type": "register", "status": "success"}).encode('utf-8'))

def handle_message(client_socket, data):
    sender = data["sender"]
    recipient = data["recipient"]
    message = data["message"]

    print(f"Message from {sender} to {recipient}: {message}")

    if recipient in clients:
        clients[recipient].send(json.dumps(data).encode('utf-8'))
    client_socket.send(json.dumps(data).encode('utf-8'))

def handle_change_password(client_socket, data):
    username = data["username"]
    old_password = data["old_password"]
    new_password = data["new_password"]
    if username in users and users[username] == old_password:
        valid, message = is_valid_password(new_password)
        if not valid:
            client_socket.send(json.dumps({"type": "change_password", "status": "failed", "message": message}).encode('utf-8'))
        else:
            users[username] = new_password
            save_users()
            client_socket.send(json.dumps({"type": "change_password", "status": "success"}).encode('utf-8'))
    else:
        client_socket.send(json.dumps({"type": "change_password", "status": "failed", "message": "Invalid old password"}).encode('utf-8'))

def start_server():
    global users
    users = load_users()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"Server started on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, client_address = server.accept()
        print(f"New connection: {client_address}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()

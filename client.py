import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from tkinter import ttk
import json
from datetime import datetime
import uuid

SERVER_HOST = '192.168.1.229'
SERVER_PORT = 8080

class ChatClient:
    def __init__(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.root.geometry("800x600")
        self.root.configure(bg='#840949')

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.login_frame = ttk.Frame(self.root, padding="20", style="TFrame")
        self.chat_frame = ttk.Frame(self.root, padding="20", style="TFrame")

        self.create_login_interface()
        self.create_chat_interface()

        self.current_user = None
        self.current_recipient = None
        self.messages = []
        self.message_ids = set()

        self.login_frame.pack(expand=True)

        self.root.mainloop()

    def generate_message_id(self):
        return str(uuid.uuid4())

    def display_message(self, message, is_new_message=True):
        sender = message['sender']
        message_text = message['message']
        timestamp = message['timestamp']
        date = timestamp.split()[0]
        time = timestamp.split()[1]

        self.chat_area.config(state=tk.NORMAL)
        if not self.chat_area.get("1.0", "end-1c").strip():
            self.chat_area.insert(tk.END, f"{date}\n", "date")

        tag = "self" if sender == self.current_user else "friend"
        time_tag = "self_time" if sender == self.current_user else "friend_time"

        if self.current_recipient:
            if sender != self.current_user:
                if self.current_recipient != sender:
                    self.chat_area.insert(tk.END, f"A new message from {sender}\n", "notification")
            self.chat_area.insert(tk.END, f"{message_text}\n", tag)
            self.chat_area.insert(tk.END, f"{time}\n", time_tag)
        else:
            self.chat_area.insert(tk.END, f"{sender}: {message_text}\n", tag)
            self.chat_area.insert(tk.END, f"{time}\n", time_tag)
        self.chat_area.tag_bind(tag, "<Button-1>", lambda event, msg=message: self.on_message_click(event, msg))

        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

        if is_new_message:
            self.messages.append(message)
            self.message_ids.add(message["id"])

    def select_user(self, event):
        selection = event.widget.curselection()
        if selection:
            selected_user = event.widget.get(selection[0])
            if " (you)" not in selected_user:
                self.current_recipient = selected_user.split(" (you)")[0]
                self.current_recipient_label.config(text=self.current_recipient)
                self.update_chat_area()

    def clear_chat(self):
        confirm = messagebox.askyesno("Confirmation of clearing the chat room", "Are you sure you want to clear the chat room?")
        if confirm:
            self.messages = []
            self.update_chat_area()

    def on_message_click(self, event, message):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Answer", command=lambda: self.reply_to_message(message))
        menu.post(event.x_root, event.y_root)

    def reply_to_message(self, message):
        self.msg_entry.insert(0, f"Response to a message from {message['sender']}: '{message['message']}'\n")

    def update_chat_area(self):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.delete(1.0, tk.END)
        for message in self.messages:
            if (message["sender"] == self.current_recipient and message["recipient"] == self.current_user) or (
                    message["sender"] == self.current_user and message["recipient"] == self.current_recipient):
                self.display_message(message, is_new_message=False)
        self.chat_area.config(state=tk.DISABLED)

    def change_password(self):
        dialog = simpledialog.Toplevel(self.root)
        dialog.title("Change password")
        dialog.configure(bg='#840949')
        dialog.geometry("400x200")

        ttk.Label(dialog, text="Enter a new password:", style="TLabel").pack(pady=5)
        new_password1_entry = ttk.Entry(dialog, style="TEntry")
        new_password1_entry.pack(pady=5)

        ttk.Label(dialog, text="Repeat the new password:", style="TLabel").pack(pady=5)
        new_password2_entry = ttk.Entry(dialog, style="TEntry")
        new_password2_entry.pack(pady=5)

        def submit_new_password():
            new_password1 = new_password1_entry.get()
            new_password2 = new_password2_entry.get()
            if new_password1 == new_password2:
                old_password = self.password_entry.get()
                self.client_socket.send(
                    json.dumps({"type": "change_password", "username": self.username_entry.get(),
                                "old_password": old_password, "new_password": new_password1}).encode('utf-8'))
                response = json.loads(self.client_socket.recv(1024).decode('utf-8'))
                if response["status"] == "success":
                    messagebox.showinfo("Change password", "Password successfully changed")
                    dialog.destroy()
                else:
                    messagebox.showerror("Change password", response["message"])
            else:
                messagebox.showerror("Error", "The new passwords don't match")

        submit_button = ttk.Button(dialog, text="Change password", command=submit_new_password, style="TButton")
        submit_button.pack(pady=5)

        cancel_button = ttk.Button(dialog, text="Cancel", command=dialog.destroy, style="TButton")
        cancel_button.pack(pady=5)

    def create_login_interface(self):
        ttk.Label(self.login_frame, text="LOGIN:", style="TLabel").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame, style="TEntry")
        self.username_entry.pack(pady=5)

        ttk.Label(self.login_frame, text="PASSWORD:", style="TLabel").pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, style="TEntry", show="*")
        self.password_entry.pack(pady=5)

        self.login_button = ttk.Button(self.login_frame, text="NEXT", command=self.login, style="TButton")
        self.login_button.pack(pady=5)

        self.register_button = ttk.Button(self.login_frame, text="REGISTRATION", command=self.register, style="TButton")
        self.register_button.pack(pady=5)

        self.change_password_button = ttk.Button(self.login_frame, text="CHANGE PASSWORD", command=self.change_password, style="TButton")
        self.change_password_button.pack(pady=5)

    def create_chat_interface(self):
        self.chat_frame.grid_rowconfigure(0, weight=1)
        self.chat_frame.grid_columnconfigure(1, weight=1)

        self.user_list_frame = ttk.Frame(self.chat_frame, style="TFrame")
        self.user_list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ns")

        self.user_list = tk.Listbox(self.user_list_frame, width=20, height=20, font=("Arial", 12), bg="#f7f9fc",
                                    borderwidth=0, highlightthickness=0)
        self.user_list.pack(side=tk.LEFT, fill=tk.Y)
        self.user_list.bind("<<ListboxSelect>>", self.select_user)

        self.chat_area_frame = ttk.Frame(self.chat_frame, style="TFrame")
        self.chat_area_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.current_recipient_label = ttk.Label(self.chat_area_frame, text="", font=("Arial", 14, "bold"), style="TLabel")
        self.current_recipient_label.pack(anchor="w")

        self.chat_area = scrolledtext.ScrolledText(self.chat_area_frame, wrap=tk.WORD, state=tk.DISABLED, font=("Arial", 12),
                                                   bg="#ffffff", borderwidth=0, highlightthickness=0)
        self.chat_area.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

        self.chat_area.tag_configure("self", justify='right', lmargin1=50, rmargin=10, background='#b8ffb8')
        self.chat_area.tag_configure("friend", justify='left', lmargin1=10, rmargin=50, background='#ffe0e0')
        self.chat_area.tag_configure("self_time", justify='right', font=("Arial", 8, "italic"))
        self.chat_area.tag_configure("friend_time", justify='left', font=("Arial", 8, "italic"))
        self.chat_area.tag_configure("date", justify='center', font=("Arial", 10, "bold"))

        self.msg_entry = ttk.Entry(self.chat_frame, width=50, font=("Arial", 12), style="TEntry")
        self.msg_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        self.msg_entry.bind("<Return>", self.send_message)

        self.clear_chat_button = ttk.Button(self.chat_frame, text="CLEAR CHAT", command=self.clear_chat,
                                            style="TButton")
        self.clear_chat_button.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        self.logout_button = ttk.Button(self.chat_frame, text="Log out of the account", command=self.logout, style="TButton")
        self.logout_button.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

        self.chat_area.tag_configure("notification", justify='left', font=("Arial", 10, "italic"), foreground="blue")

    def logout(self):
        confirm = messagebox.askyesno("Confirmation of exit", "Are you sure you want to log out of your account?")
        if confirm:
            self.client_socket.close()
            self.save_user_chats()
            self.root.destroy()
            client = ChatClient(SERVER_HOST, SERVER_PORT)

    def login(self):
        SERVER_HOST = self.password_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Login failed", "Username or password cannot be empty")
            return
        self.client_socket.send(
            json.dumps({"type": "login", "username": username, "password": password}).encode('utf-8'))
        response = json.loads(self.client_socket.recv(1024).decode('utf-8'))
        if response["status"] == "success":
            self.current_user = username
            self.load_user_chats()  # Добавлено
            self.login_frame.pack_forget()
            self.chat_frame.pack(fill=tk.BOTH, expand=True)
            threading.Thread(target=self.receive_messages).start()
        else:
            messagebox.showerror("Login failed", "Invalid username or password")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Registration failed", "Username or password cannot be empty")
            return
        self.client_socket.send(
            json.dumps({"type": "register", "username": username, "password": password}).encode('utf-8'))
        response = json.loads(self.client_socket.recv(1024).decode('utf-8'))
        if response["status"] == "success":
            messagebox.showinfo("Registration successful", "You can now login")
        else:
            messagebox.showerror("Registration failed", response["message"])

    def send_message(self, event):
        message = self.msg_entry.get().strip()
        if message and self.current_recipient:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
            message_id = self.generate_message_id()
            message_data = {"type": "message", "id": message_id, "sender": self.current_user, "recipient": self.current_recipient,
                            "message": message, "timestamp": timestamp}
            self.client_socket.send(json.dumps(message_data).encode('utf-8'))
            self.msg_entry.delete(0, tk.END)
            self.display_message(message_data)

    def receive_messages(self):
        while True:
            try:
                message = json.loads(self.client_socket.recv(1024).decode('utf-8'))
                if message["type"] == "user_list":
                    self.update_user_list(message["users"])
                elif message["type"] == "message":
                    if message["id"] not in self.message_ids:
                        self.messages.append(message)
                        self.message_ids.add(message["id"])
                    if message["sender"] == self.current_recipient or message["recipient"] == self.current_user:
                        self.display_message(message, is_new_message=False)
            except:
                print("Error receiving message.")
                self.client_socket.close()
                break

    def update_user_list(self, users):
        self.user_list.delete(0, tk.END)
        if self.current_user in users:
            users.remove(self.current_user)
            users.insert(0, self.current_user)
        for user in users:
            display_name = f"{user} (you)" if user == self.current_user else user
            self.user_list.insert(tk.END, display_name)

    def on_closing(self):
        self.client_socket.close()
        self.save_user_chats()
        self.root.destroy()

    def load_user_chats(self):
        try:
            with open(f"{self.current_user}_chats.json", "r") as file:
                saved_messages = json.load(file)
                for message in saved_messages:
                    if message["id"] not in self.message_ids:
                        self.messages.append(message)
                        self.message_ids.add(message["id"])
                self.update_chat_area()
        except FileNotFoundError:
            self.messages = []

    def save_user_chats(self):
        with open(f"{self.current_user}_chats.json", "w") as file:
            json.dump(self.messages, file)

if __name__ == "__main__":
    client = ChatClient(SERVER_HOST, SERVER_PORT)

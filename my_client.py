import socket
from threading import Thread
from datetime import datetime

from encoding import Encrypting

# server's IP address
# if the server is not on this machine, 
# put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002 # server's port
separator_token = "<SEP>" # we will use this to separate the client name & message
padding_token = "<PAD>"

# initialize TCP socket
s = socket.socket()
print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print("[+] Connected.")

server_public = s.recv(1024).decode()
server_public = tuple(map(int,server_public[1:-1].split(', ')))

client_public, client_private = Encrypting().get_keys()

client_public_encoded = Encrypting().encrypt_message(str(client_public), server_public)
s.send(str(client_public_encoded).encode())
print(server_public)
# prompt the client for a name
name = input("Enter your name: ")

def listen_for_messages():
    while True:
        message = Encrypting().decrypt_message(s.recv(1024).decode(), client_private)
        print("\n" + message)

# make a thread that listens for messages to this client & print them
t = Thread(target=listen_for_messages)
# make the thread daemon so it ends whenever the main thread ends
t.daemon = True
# start the thread
t.start()

while True:
    # input message we want to send to the server
    to_send =  input()
    # a way to exit the program
    if to_send.lower() == 'q':
        break
    # add the datetime, name & the color of the sender
    date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
    to_send = f"[{date_now}] {name}{separator_token}{to_send}"
    # finally, send the message
    s.send(Encrypting().encrypt_message(to_send, server_public).encode())

# close the socket
s.close()
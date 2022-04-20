import socket
import threading
from encoding import Encoding, Encrypting

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    def generate_keys(self):
        public_server_key = Encrypting.get_public_key()
        private_server_key = Encrypting.get_private_key()
        return public_server_key, private_server_key

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...
        public, private = self.generate_keys()
        

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect.")
            self.broadcast(f'New person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client 
            c.send(public.encode())
            # ...
            user_public = c.recv(1024)
            # encrypt the secret with the clients public key
            
            # ...

            # send the encrypted secret to a client 

            # ...

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients: 

            # encrypt the message

            # ...

            client.send(msg.encode())

    def handle_client(self, c: socket, addr): 
        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    client.send(msg)

if __name__ == "__main__":
    s = Server(9001)
    s.start()

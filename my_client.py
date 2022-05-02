import socket
from threading import Thread
from datetime import datetime
from hashlib import sha256
from encoding import Encrypting


class Client:
    def __init__(
        self, server_host: str = None, server_port: int = None, username: str = None
    ) -> None:
        # server's IP address
        # if the server is not on this machine,
        # put the private (network) IP address (e.g 192.168.1.2)
        self.SERVER_HOST = server_host or "127.0.0.1"
        self.SERVER_PORT = server_port or 5002  # server's port
        self.separator_token = (
            "<SEP>"  # we will use this to separate the client name & message
        )
        self.padding_token = "~"  # we will use this to separate the hash
        # initialize TCP socket
        self.s = socket.socket()
        print(f"[*] Connecting to {self.SERVER_HOST}:{self.SERVER_PORT}...")
        # connect to the server
        self.s.connect((self.SERVER_HOST, self.SERVER_PORT))
        print("[+] Connected.")

    def __exchange_keys(self):
        # receive the server's public key
        self.server_public = self.s.recv(1024).decode()
        self.server_public = tuple(map(int, self.server_public[1:-1].split(", ")))
        # generate a new pair of keys for client
        self.client_public, self.client_private = Encrypting().get_keys()
        # send the client's public key to the server
        client_public_encoded = Encrypting().encrypt_message(
            str(self.client_public), self.server_public
        )
        self.s.send(str(client_public_encoded).encode())
        print(self.server_public)

    def run(self) -> None:

        self.__exchange_keys()

        # prompt the client for a name
        name = input("Enter your name: ")

        # make a thread that listens for messages to this client & print them
        t = Thread(target=self.listen_for_messages)
        # make the thread daemon so it ends whenever the main thread ends
        t.daemon = True
        # start the thread
        t.start()

        while True:
            # input message we want to send to the server
            to_send = ""
            while to_send == "":
                to_send = input()
            # a way to exit the program
            if to_send.lower() == "q":
                break
            # add the datetime, name of the sender
            date_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            to_send = f"[{date_now}] {name}{self.separator_token}{to_send}".strip()
            # finally, send the message
            try:
                # special symbol for separataing hash and message
                if "~" in to_send:
                    raise KeyError
                self.send_message(to_send)
            except KeyError:
                print(
                    "[!] Unable to encrypt message! Check for characters that are not in dictionary."
                )

    def listen_for_messages(self) -> None:
        while True:
            # receive the packet from the server
            packet = self.s.recv(1024).decode()
            msg_hash, message = (
                Encrypting()
                .decrypt_message(packet, self.client_private)
                .split(self.padding_token)
            )
            # check if the hash matches the message
            if sha256(message.strip().encode()).hexdigest() != msg_hash:
                print("[!] Message was tampered with!")
                continue
            print("\n" + message)

    def send_message(self, message: str) -> None:
        # send the message to the server
        self.s.send(
            (
                Encrypting().encrypt_message(
                    sha256(message.strip().encode()).hexdigest()
                    + self.padding_token
                    + message,
                    self.server_public,
                )
            ).encode()
        )

    def close(self) -> None:
        # close the socket
        self.s.close()


if __name__ == "__main__":
    client = Client(server_port=5002)
    client.run()
    client.close()

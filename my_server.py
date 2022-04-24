import socket
from threading import Thread
from encoding import Encrypting
class Server:
    def __init__(self, port: int = None, host: str = None) -> None:

        # server's IP address
        self.SERVER_HOST = host or "0.0.0.0"
        self.SERVER_PORT = port or 5002  # port we want to use
        self.separator_token = "<SEP>"  # we will use this to separate the client name & message
        self.padding_token = "<PAD>"
        # initialize list/set of all connected client's sockets
        self.client_sockets = set()
        self.client_keys = {}
        # create a TCP socket

        self.s = socket.socket()
        # make the port as reusable port
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 128)
        # bind the socket to the address we specified
        self.s.bind((self.SERVER_HOST, self.SERVER_PORT))

    def start(self):
        # listen for upcoming connections
        self.s.listen(5)
        print(f"[*] Listening as {self.SERVER_HOST}:{self.SERVER_PORT}")
# generates a new pair of keys for server
        self.server_public, self.server_private = Encrypting().get_keys()


        while True:
            # we keep listening for new connections all the time
            client_socket, client_address = self.s.accept()
            print(f"[+] {client_address} connected.")
            # add the new connected client to connected sockets
            self.client_sockets.add(client_socket)

            client_socket.send(str(self.server_public).encode())
            client_public = client_socket.recv(1024).decode()
            client_public = Encrypting().decrypt_message(client_public, self.server_private)

            self.client_keys[str(client_socket)] = tuple(
                map(int, client_public.rstrip()[1:-1].split(", "))
            )
            # start a new thread that listens for each client's messages
            t = Thread(target=self.listen_for_client, args=(client_socket,))
            # make the thread daemon so it ends whenever the main thread ends
            t.daemon = True
            # start the thread
            t.start()

    def listen_for_client(self,cs):
        """
        This function keep listening for a message from `cs` socket
        Whenever a message is received, broadcast it to all other connected clients
        """
        while True:
            try:
                # keep listening for a message from `cs` socket
                msg = Encrypting().decrypt_message(cs.recv(1024).decode(), self.server_private)
            except Exception as e:
                # client no longer connected
                # remove it from the set
                print(f"[!] Error: {e}")
                self.client_sockets.remove(cs)
            else:
                # if we received a message, replace the <SEP>
                # token with ": " for nice printing
                msg = msg.replace(self.separator_token, ": ")
            # iterate over all connected sockets
            for client_socket in self.client_sockets:
                if client_socket != cs:
                    # and send the message to all other clients
                    client_socket.send(
                        Encrypting()
                        .encrypt_message(msg, self.client_keys[str(client_socket)])
                        .encode()
                    )
    def close(self):
        # close client sockets
        for cs in self.client_sockets:
            cs.close()
        # close server socket
        self.s.close()

if __name__ == "__main__":
    # create a server object
    server = Server(port=5002)
    # start the server
    server.start()
    # close the server
    server.close()

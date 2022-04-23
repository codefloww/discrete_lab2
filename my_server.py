import socket
from threading import Thread
from encoding import Encrypting

# server's IP address
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002  # port we want to use
separator_token = "<SEP>"  # we will use this to separate the client name & message
padding_token = "<PAD>"
# initialize list/set of all connected client's sockets
client_sockets = set()
client_keys = {}
# create a TCP socket

s = socket.socket()
# make the port as reusable port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 128)
# bind the socket to the address we specified
s.bind((SERVER_HOST, SERVER_PORT))
# listen for upcoming connections
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
# generates a new pair of keys for server
server_public, server_private = Encrypting().get_keys()


def listen_for_client(cs):
    """
    This function keep listening for a message from `cs` socket
    Whenever a message is received, broadcast it to all other connected clients
    """
    while True:
        try:
            # keep listening for a message from `cs` socket
            msg = Encrypting().decrypt_message(cs.recv(1024).decode(), server_private)
        except Exception as e:
            # client no longer connected
            # remove it from the set
            print(f"[!] Error: {e}")
            client_sockets.remove(cs)
        else:
            # if we received a message, replace the <SEP>
            # token with ": " for nice printing
            msg = msg.replace(separator_token, ": ")
        # iterate over all connected sockets
        for client_socket in client_sockets:
            if client_socket != cs:
                # and send the message to all other clients
                client_socket.send(
                    Encrypting()
                    .encrypt_message(msg, client_keys[str(client_socket)])
                    .encode()
                )


while True:
    # we keep listening for new connections all the time
    client_socket, client_address = s.accept()
    print(f"[+] {client_address} connected.")
    # add the new connected client to connected sockets
    client_sockets.add(client_socket)

    client_socket.send(str(server_public).encode())
    client_public = client_socket.recv(1024).decode()
    client_public = Encrypting().decrypt_message(client_public, server_private)

    client_keys[str(client_socket)] = tuple(
        map(int, client_public.rstrip()[1:-1].split(", "))
    )
    # start a new thread that listens for each client's messages
    t = Thread(target=listen_for_client, args=(client_socket,))
    # make the thread daemon so it ends whenever the main thread ends
    t.daemon = True
    # start the thread
    t.start()

# close client sockets
for cs in client_sockets:
    cs.close()
# close server socket
s.close()

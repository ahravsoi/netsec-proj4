import socket
import argparse
import json
import signal
import sys
import threading

class Client:
    def __init__(self, username, ip, port):
        self.server_address = (ip, port)
        self.username = username
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.known_peers = {}  # Map of {username: (ip, listner_port)}
        self.server_lock = threading.Lock()

        # Create a seperate socket that will listen to incoming messages from other clients
        self.client_listnener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_listnener.bind((ip, 0))  # Bind to any available port
        self.client_listener_port = self.client_listnener.getsockname()[1] # Server should tell other clients to send messages to this port
        self.client_listnener.listen(5)  # Listen for incoming connections
        

    def connect_to_server(self):
        try:
            self.server_socket.connect(self.server_address)
            self.connected = True
            print(f'[*] Connected to server at {self.server_address}')
    
            self.login(self.username) # Send login request upon connection
            threading.Thread(target=self.serverListener, daemon=True).start() # Starts a thread to receive messages from server
            signal.signal(signal.SIGINT, self.logout)  # Handle Ctrl+C to logout FIX THIS LINE
        except socket.error as e:
            print(f'[*] Connection error: {e}')
    
    def message_server(self, packet):
        try:
            with self.server_lock:
                self.server_socket.send(json.dumps(packet).encode('utf-8'))
        except Exception as e:
            print(f'[*] Error sending message to server: {e}')

    def run(self):
        '''
            Start peer listener
            Start the command line interface for the client to handle user inputted commands
            Commands:
                - LIST: List all users
                - SEND <username> <message>: Send a message to a user
            
            Supports keyboard interrupts to logout
        '''
        threading.Thread(target=self.peerListener, daemon=True).start()  # Start listening for incoming messages from other clients
        self.connect_to_server()  # Connect to the server
        while self.connected: # CLI loop
            try:
                command = input("Please Enter command:\n")
                command_parts = command.split(maxsplit=2)
                if command_parts[0].lower() == 'list':
                    rsp = self.handleLIST()
                elif len(command_parts) == 3 and command_parts[0].lower() == 'send':
                    destination_username = command_parts[1]
                    message = command_parts[2]
                    rsp = self.handleSEND(destination_username, message)
                else:
                    print("Invalid command. Please try again.")
                
                if rsp is not None:
                    print(rsp)
            except KeyboardInterrupt:
                print("Logging out")
                self.logout()
            except Exception as e:
                print(f'Error while listening for user commands: {e}')
   
    def serverListener(self):
        '''
            Continuously receive messages from the server
        '''
        while self.connected:
            try:
                data = self.server_socket.recv(1024)  # Receiving in chunks of 1024 bytes
                if not data:
                    print("[*] Server closed the connection.")
                    self.connected = False
                    break
                message = json.loads(data.decode('utf-8'))
                print(f'[*] Received message: {message}')

                msg_type = message.get('type')
                print(f'[*] Message type: {msg_type}')
                if msg_type == 'RESPONSE':
                    print(f'{message.get("message")}')
                elif msg_type == 'ADDRESS':
                    self.known_peers[message.get('requested_user_username')] = (message.get('requested_user_ip'), message.get('requested_user_listener_port'))
                else :
                    print(f'[*] Unknown message type: {msg_type}')
                print("Please Enter Command:", end='\n', flush=True)

            except Exception as e:
                print(f'[*] Error receiving message: {e}')
                self.connected = False
                break
        
    def peerListener(self):
        '''
            Continuously receive connections from other clients on our listener socket.
            When a connection is received, spawn a new thread to handle the connection.
        '''
        while True:
            try:
                conn, addr = self.client_listnener.accept()  # Accept incoming connections
                threading.Thread(target=self.handle_peer_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f'[*] Error accepting connection: {e}')
                break

    def handle_peer_connection(self, conn, addr):
        '''
            Handle incoming connections from other clients.
            This is where we will receive messages from other clients.

            Only expect one type of message from the clients - MESSAGE
        '''
        try:
            data = conn.recv(1024)  # Receiving in chunks of 1024 bytes
            if not data:
                print("[*] Peer closed the connection.")
                return
            message = json.loads(data.decode('utf-8'))
            if message.get('type') == 'MESSAGE':
                print(f'<From {message.get("source_ip")}:{message.get("source_port")}:{message.get("source_user")}> {message.get("message")} ')
            else:
                print(f'[*] Unknown message type: {message.get("type")}')
        except Exception as e:
            print(f'[*] Error receiving message from peer: {e}')
        finally:
            conn.close()

    def logout(self, signum=None, frame=None):
        packet = {
            "type": "SIGN-OUT",
            "username": self.username
        }
        self.message_server(packet)
        self.running = False
        #self.close()
        sys.exit(0)

    def login(self, username):
        packet = {
            "type": "SIGN-IN",
            "username": username,
            "reciever_port": self.client_listener_port
        }
        self.message_server(packet)

    def handleLIST(self):
        packet = {
            "type": "LIST",
            "username": self.username
        }
        self.message_server(packet)

    def handleSEND(self, dest_user, msg):
        '''
            Sends message to dest user. 
        '''
        packet = {
            "type": "MESSAGE",
            "source_ip": 0, # Need to figure out how to get the local ip address
            "source_port": 0, # Need to figure out how to get the local port
            "source_user": self.username,
            "to": dest_user,
            "message": msg
        }
        dest = self.get_destAddress(dest_user) # or request the address from the server
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
                peer_socket.connect(dest) # Open temporary socket to send the message
                peer_socket.send(json.dumps(packet).encode('utf-8'))
                print(f"Message sent to {dest_user} at {dest}")
        except Exception as e:
            print(f"Error sending message to {dest_user}. They may not be signed in: {e}")
    
    def get_destAddress(self, dest_user):
        '''
            Get the address of the destination user. If the destination user is not in the known_peers cache,
            it will request the address from the server and wait until the peers table is updated.
        '''
        if dest_user in self.known_peers:
            return self.known_peers[dest_user]
        else:
            packet = {
                "type": "ADDRESS_REQUEST",
                "source_user": self.username,
                "requested_user": dest_user
            }
            self.message_server(packet)
            while dest_user not in self.known_peers: # Wait for the local peers table to get updated
                pass
            return self.known_peers[dest_user]

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', type=str, help='Username')
    parser.add_argument('-sip', type=str, help='Server IP address', default='127.0.0.1')
    parser.add_argument('-sp', type=int, help='Server port number')
    args = parser.parse_args()
    client = Client(args.u, args.sip, args.sp)
    client.run()

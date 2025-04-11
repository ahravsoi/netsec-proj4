import socket
import json
import signal
import sys
import threading
import os
import binascii

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Client:
    def __init__(self, ip, port):
        '''
            Initialize the client with the server address and create a socket that will later connect to the server
            Also creates an lisenting socket that will be used to listen for incoming messages from other clients (seperate port number as well)
        '''
        self.server_address = (ip, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.login_status = False
        self.known_peers = {}  # Map of {username: (ip, listner_port)}

        self.server_lock = threading.Lock()
        self.key_exchange_events = {}  # {username: threading.Event()}


        # Get the current IP address of the client
        self.current_ip = socket.gethostbyname(socket.gethostname())

        # Create a seperate socket that will listen to incoming messages from other clients
        self.client_listnener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_listnener.bind((ip, 0))  # Bind to any available port
        self.client_listener_port = self.client_listnener.getsockname()[1] # Server should tell other clients to send messages to this port
        self.client_listnener.listen(5)  # Listen for incoming connections

        # Handle all the keys that this client learns
        self.ephemeral_keys = {}  # {username: public_key}
        self.shared_keys = {}     # {username: shared_key}

        # Our keys make sure to dump them
        self.priv = ''
        
    def connect_to_server(self):
        '''
            Connect to the server and start a thread to listen for incoming messages from the server
        '''
        try:
            self.server_socket.connect(self.server_address)
            self.connected = True
            print(f'[*] Connected to server at {self.server_address}')

            threading.Thread(target=self.serverListener, daemon=True).start() # Starts a thread to receive messages from server
            signal.signal(signal.SIGINT, self.logout)  # Handle Ctrl+C to logout FIX THIS LINE
        except socket.error as e:
            print(f'[*] Connection error: {e}')
            os._exit(1)
    
    def message_server(self, packet):
        '''
            Used only when sending messages to the server
        '''
        try:
            with self.server_lock:
                self.server_socket.send(json.dumps(packet).encode('utf-8'))
        except Exception as e:
            print(f'[*] Error sending message to server: {e}')

    def message_peer(self, dest_user, packet):
        '''
            Used only when sending messages to the peer
        '''
        while dest_user not in self.known_peers: # Wait for the local peers table to get updated
            #print(f'Known Peers: {self.known_peers}')
            pass
        peer_ip, peer_port = self.known_peers.get(dest_user)
        # print(f'[DEBUG] Peer IP: {peer_ip}, Peer Port: {peer_port}')
        if peer_ip and peer_port:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
                peer_socket.connect((peer_ip, peer_port))
                sent = peer_socket.send(json.dumps(packet).encode('utf-8')) # Send a response back to the peer
                #print(f'[+] Sent response to {peer_ip}:{peer_port}: {packet}. Bytes sent: {sent}')
        # else:
        #     print(f'[-] Peer {dest_user} not found in known peers.')

    def run(self):
        '''
            Start peer listener
            Start the command line interface for the client to handle user inputted commands
            Starts a thread to listen for incoming connections from other clients
            Commands:
                - LIST: List all users
                - SEND <username> <message>: Send a message to a user
            
            Supports keyboard interrupts to logout
        '''
        self.connect_to_server()  # Connect to the server
        
        self.username = input("Enter your username: ")
        self.password = input("Enter your password: ")
        self.login(self.username, self.password)  # Send login request upon connection
        while not self.login_status:
            pass  # Wait until the serverListener updates the login_status
        threading.Thread(target=self.peerListener, daemon=True).start()  # Start listening for incoming messages from other clients
        
        while self.connected and self.login_status: # CLI loop
            try:
                command = input(f'{self.username}@{self.current_ip}: Enter Command>>\n')
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
            Continuously receive messages from the server. This is the method used in the thread in the connect_to_server method.
        '''
        while self.connected:
            try:
                data = self.server_socket.recv(1024)  # Receiving in chunks of 1024 bytes
                if not data:
                    print("[*] Server closed the connection.")
                    self.connected = False
                    break
                message = json.loads(data.decode('utf-8'))

                msg_type = message.get('type')
                if msg_type == 'RESPONSE':
                    print(f'{message.get("message")}')
                    print(f'{self.username}@{self.current_ip}: Enter Command>>', flush=True)
                elif msg_type == 'ADDRESS':
                    self.known_peers[message.get('requested_user_username')] = (message.get('requested_user_ip'), message.get('requested_user_listener_port'))
                elif msg_type == 'LOGIN_SUCCESS':
                    self.login_status = True
                    print(f'[+] Login successful. Welcome {self.username}!')
                    # print(f'{self.username}@{self.current_ip}: Enter Command>>\n', flush=True)
                elif msg_type == 'LOGIN_FAIL':
                    self.login_status = False
                    print(f'[-] Login failed: {message.get("message")}\nPlease restart the application and try again.')
                    self.running = False
                    os._exit(0)
                else :
                    print(f'[-] Unknown message type: {msg_type}')
                    # print(f'{self.username}@{self.current_ip}: Enter Command>>\n', flush=True)

            except Exception as e:
                print(f'[*] Error receiving message: {e}')
                self.connected = False
                break
        
    def peerListener(self):
        '''
            Continuously receive connections from other clients on our listener socket.
            When a connection is received, spawn a new thread to handle the connection and then listen for messages
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
            Handle a single connection for a inbound client, this will run in a seperate thread for each client. 
                - Say we have 4 clients connected, there will be 4 threads running this method.
            This is where we will open a socket with the client so that we can recieve and communicate.

            This will handle inbound messages:
                - KEY_EXCHANGE
                - MESSAGE
                - KEY_EXCHANGE_RESPONSE
        '''
        try:
            data = conn.recv(1024)  # Receiving in chunks of 1024 bytes
            if not data:
                print("[*] Peer closed the connection.")
                return
            data = json.loads(data.decode('utf-8'))
            if data.get('type') == 'MESSAGE':
                # Decrypt the message using the shared key
                recieved_message = self.handleRecievedMessage(data)
                print(f'<From {data.get("source_ip")}:{data.get("source_port")}:{data.get("source_user")}> {recieved_message}')
                print(f'{self.username}@{self.current_ip}: Enter Command>>\n', flush=True)
            elif data.get('type') == 'KEY_EXCHANGE':
                rsp = self.handleKeyExchange(data, conn, data.get("public_key"), data.get("source_user"))
                # At this point we need to generate the session key too because we have the public key of the peer and then generating our own in
                # the method above 
                self.message_peer(data.get("source_user"), rsp)
            elif data.get('type') == 'KEY_EXCHANGE_RESPONSE':
                session_key = self.generateSharedSessionKey(self.priv, data.get("public_key").encode('utf-8'), data.get("source_user"))
                # Send the actual message now which is tricky because the logic is in the else clause of the send method


            else:
                print(f'[*] Unknown message type: {data.get("type")}')
                print(f'{self.username}@{self.current_ip}: Enter Command>>\n', flush=True)
            


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
        sys.exit(0)

    def login(self, username, password):
        packet = {
            "type": "SIGN-IN",
            "username": username,
            "password": password,
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
            Creates a temporary socket with the destination user and sends the message.
        '''
        dest = self.get_destAddress(dest_user) # or request the address from the server

        if dest_user not in self.shared_keys:
            private_key, public_key = self.generateKeyPair()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            #self.ephemeral_keys[dest_user] = public_key_bytes.decode('utf-8') this seems wrong
        
            packet = { # Send our public key to the destination user
                "type": "KEY_EXCHANGE",
                "source_user": self.username,
                "public_key": public_key_bytes.decode('utf-8'),
                "source_ip": self.server_socket.getsockname()[0],  # Get the local IP address
                "source_port": self.client_listener_port  # Include the listening port
            }

            self.key_exchange_events[dest_user] = threading.Event()  # Create an event for the key exchange
            
            try:
                self.message_peer(dest_user, packet)  # Send the key exchange packet
            except Exception as e:
                print(f"Error sending key exchange message to {dest_user}: {e}")

            self.key_exchange_events[dest_user].wait(5)  # Set time out and wait for key exchange to complete
            if dest_user not in self.shared_keys:
                print(f'[-] Key exchange timed out with {dest_user}.')
                return

        
    
        
        # Now that shared key is derived, we can encrypt the message
        nonce, ciphertext_msg = self.encrypt_message(self.shared_keys[dest_user], msg)

        packet = {
            "type": "MESSAGE",
            "source_ip": self.current_ip, # Need to figure out how to get the local ip address
            "source_port": self.client_listener_port, # Need to figure out how to get the local port
            "source_user": self.username,
            "to": dest_user,
            "nonce": binascii.hexlify(nonce).decode('utf-8'),
            "message": binascii.hexlify(ciphertext_msg).decode('utf-8')
        }
        try:
            self.message_peer(dest_user, packet)  # Send the key exchange packet
        except Exception as e:
            print(f"Error sending message packet to {dest_user}: {e}")


    def handleKeyExchange(self, data, conn, sender_pub_key, sender_username):
        '''
            For now we just want to respond to the key exchange request by sending back our public key.
            Add the sender to known peers
        '''
        # Add the source user to known peers
        self.known_peers[data["source_user"]] = (data["source_ip"], data["source_port"])
        private_key, public_key = self.generateKeyPair()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
        self.generateSharedSessionKey(self.priv, sender_pub_key.encode('utf-8'), data["source_user"])

        # Store the ephemeral key and shared key
        self.ephemeral_keys[data["source_user"]] = data["public_key"]
        packet = {
            "type": "KEY_EXCHANGE_RESPONSE",
            "source_user": self.username,
            "public_key": public_key_bytes.decode('utf-8')
        }
        return packet

    def handleRecievedMessage(self, data):
        if self.shared_keys.get(data.get("source_user")):
            nonce = binascii.unhexlify(data.get("nonce"))
            ciphertext = binascii.unhexlify(data.get("message"))
            try:
                plaintext = self.decrypt_message(self.shared_keys[data.get("source_user")], nonce, ciphertext)
                return plaintext
            except Exception as e:
                print(f'[-] Error decrypting message: {e}')
                return None
        else:
            print(f'[-] No shared key found for {data.get("source_user")}. Cannot decrypt message.')
            return None

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

    def generateKeyPair(self):
        '''
            Generate a public/private key pair using ECDSA
        '''
        self.priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub = self.priv.public_key()
        return self.priv, pub
    
    def generateSharedSessionKey(self, private_key, peer_public_key_bytes, peer_username):
        '''''
            Generate a shared secret key using ECDH
        '''
        peer_pub_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = private_key.exchange(ec.ECDH(), peer_pub_key)

        # Derive a symmetric key from the shared secret using HKDF
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        print(f'[*] Generated Shared Session Key with {peer_username}: {binascii.hexlify(session_key)}')
        self.shared_keys[peer_username] = session_key
        if peer_username in self.key_exchange_events:
            self.key_exchange_events[peer_username].set()

        return session_key
    
    def encrypt_message(self, shared_key, plaintext):
        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return nonce, ciphertext

    def decrypt_message(self, shared_key, nonce, ciphertext):
        aesgcm = AESGCM(shared_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

if __name__ == '__main__':
    # Load server configuration from config.json
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            sip = config.get('server_ip')
            sp = config.get('server_port')
    except FileNotFoundError:
        print("[*] config.json not found. Using default values.")
    except json.JSONDecodeError as e:
        print(f"[*] Error parsing config.json: {e}. Using default values.")
    client = Client(sip, sp)
    client.run()

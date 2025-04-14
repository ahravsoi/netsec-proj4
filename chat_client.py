import socket
import json
import signal
import sys
import threading
import os
import binascii
import time
import base64
import logging
import hashlib
import secrets
import random
import hmac  
from typing import Dict, Tuple, Optional, List, Any
import uuid
import argparse

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("client")

class SRPClient:
    """Implements SRP (Secure Remote Password) protocol for the client"""
    
    def __init__(self):
        # SRP parameters
        # N = Large safe prime (RFC 5054 Group 2, 1024-bit)
        self.N = 0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73
        self.g = 2  # Generator
        self.k = 3  # Multiplier parameter (k=3 for SRP-6a)
        
    def generate_salt(self) -> bytes:
        """Generate a random salt"""
        return secrets.token_bytes(16)
    
    def compute_verifier(self, username: str, password: str, salt: bytes) -> int:
        """Compute the password verifier v = g^x % N"""
        # Calculate x = H(salt | H(username | ":" | password))
        username_password = f"{username}:{password}".encode('utf-8')
        h_up = hashlib.sha256(username_password).digest()
        x_hash = hashlib.sha256(salt + h_up).digest()
        x = int.from_bytes(x_hash, byteorder='big')
        
        # Calculate v = g^x % N
        v = pow(self.g, x, self.N)
        logger.debug(f"SRP: Generated verifier for {username} (bit length: {v.bit_length()})")
        return v
    
    def compute_client_proof(self, username: str, salt: bytes, A: int, B: int, 
                            x: int, a: int) -> Tuple[bytes, bytes]:
        """
        Compute the client proof M and the session key K
        Returns (client_proof, session_key)
        """
        # Calculate u = H(A | B)
        u_hash = hashlib.sha256(str(A).encode() + str(B).encode()).digest()
        u = int.from_bytes(u_hash, byteorder='big')
        
        # Calculate session key: S = (B - k * g^x) ^ (a + u * x) % N
        S = pow(B - self.k * pow(self.g, x, self.N) % self.N, a + u * x, self.N)
        S_bytes = S.to_bytes((S.bit_length() + 7) // 8, byteorder='big')
        K = hashlib.sha256(S_bytes).digest()
        
        # Calculate client proof: M = H(H(N) XOR H(g) | H(username) | salt | A | B | K)
        h_N = hashlib.sha256(str(self.N).encode()).digest()
        h_g = hashlib.sha256(str(self.g).encode()).digest()
        h_I = hashlib.sha256(username.encode()).digest()
        
        # XOR h_N and h_g
        h_Ng = bytes(a ^ b for a, b in zip(h_N, h_g))
        
        # Combine all parts
        M_parts = h_Ng + h_I + salt + str(A).encode() + str(B).encode() + K
        M = hashlib.sha256(M_parts).digest()
        
        logger.debug(f"SRP: Generated client proof and session key for {username}")
        return M, K
    
    def verify_server_proof(self, A: int, M: bytes, K: bytes, HAMK: bytes) -> bool:
        """Verify the server's proof"""
        # Calculate expected server proof: H(A | M | K)
        expected_HAMK = hashlib.sha256(str(A).encode() + M + K).digest()
        
        # Verify server proof using constant-time comparison
        result = hmac.compare_digest(expected_HAMK, HAMK)
        logger.debug(f"SRP: Server proof verification {'successful' if result else 'failed'}")
        return result


class Client:
    def __init__(self, ip, port, debug=False):
        """Initialize the client with the server address and ports"""
        self.server_address = (ip, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.login_status = False
        self.username = None
        self.running = True
        
        # Set debug mode
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Get the current IP address of the client
        self.current_ip = socket.gethostbyname(socket.gethostname())
        
        # Create a socket that will listen for incoming messages from other clients
        self.client_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_listener.bind((ip, 0))  # Bind to any available port
        self.client_listener_port = self.client_listener.getsockname()[1]
        self.client_listener.listen(5)
        
        # Thread synchronization
        self.server_lock = threading.Lock()
        self.peers_lock = threading.Lock()
        self.keys_lock = threading.Lock()
        self.key_exchange_events = {}  # {username: threading.Event()}
        self.console_lock = threading.Lock()  # Lock for console output
        
        # Event to handle command input synchronized with server responses
        self.login_complete = threading.Event()
        
        # Peer information and key management
        self.known_peers = {}  # {username: (ip, listener_port)}
        self.ephemeral_keys = {}  # {username: {"private_key": bytes, "public_key": bytes, "timestamp": int}}
        self.shared_keys = {}  # {username: {"key": bytes, "timestamp": int, "messages_sent": int, "messages_received": int}}
        
        # Message history and session management
        self.message_history = {}  # {username: [{"timestamp": int, "sender": str, "message": str, "outbound": bool}]}
        
        # SRP protocol handler
        self.srp_client = SRPClient()
        
        # SRP session data
        self.srp_data = None
        
        # Default users for quick login
        self.default_users = [
            {"username": "alice", "password": "password1"},
            {"username": "bob", "password": "password2"},
            {"username": "charlie", "password": "password3"}
        ]
        
        # Create data directory if it doesn't exist - only for message history, not keys
        self.data_dir = os.path.expanduser("~/.secure_messenger")
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Set proper permissions for data directory
        try:
            os.chmod(self.data_dir, 0o700)  # Only owner can read/write/execute
            logger.debug(f"SECURITY: Set 0o700 permissions on {self.data_dir}")
        except Exception as e:
            logger.warning(f"Could not set permissions on data directory: {e}")
        
        # Initialize message replay protection
        self.recent_message_ids = set()  # Store recent message IDs to prevent replay
        logger.debug("SECURITY: Initialized message replay protection")
        
        # For tracking the last time we sent a real message (for dummy traffic)
        self.last_real_message_time = 0
        
        # Start dummy traffic thread for enhanced privacy
        threading.Thread(target=self.schedule_dummy_traffic, daemon=True).start()
        logger.debug("ENDPOINT-HIDING: Started dummy traffic generator thread")
        
        # Endpoint hiding - schedule periodic port rotations
        threading.Thread(target=self.schedule_port_rotation, daemon=True).start()
        logger.debug("ENDPOINT-HIDING: Started port rotation scheduler thread")
        
    def schedule_dummy_traffic(self):
        """Generate dummy traffic to mask communication patterns"""
        # Wait for login before starting
        while not self.login_status and self.running:
            time.sleep(5)
            
        logger.debug("ENDPOINT-HIDING: Dummy traffic generator active")
        while self.running and self.login_status:
            # Sleep for random interval (5-15 minutes)
            interval = random.uniform(300, 900)
            time.sleep(interval)
            
            # Only send dummy traffic if we haven't sent real messages recently
            if time.time() - self.last_real_message_time > 600:  # No real messages in 10 minutes
                # Get list of potential recipients
                with self.peers_lock:
                    online_users = list(self.known_peers.keys())
                
                if online_users and len(online_users) > 0:
                    target = random.choice(online_users)
                    if target != self.username:
                        # Send dummy message with special flag
                        logger.info(f"ENDPOINT-HIDING: Sending dummy traffic to {target}")
                        try:
                            self.handle_send(target, f"DUMMY_{secrets.token_hex(8)}", is_dummy=True)
                        except Exception as e:
                            logger.debug(f"Failed to send dummy traffic: {e}")

    def schedule_port_rotation(self):
        """Periodically rotate listening port for enhanced endpoint hiding"""
        # Wait for login before starting
        while not self.login_status and self.running:
            time.sleep(5)
            
        logger.debug("ENDPOINT-HIDING: Port rotation scheduler active")
        while self.running and self.login_status:
            # Sleep for random interval (30-60 minutes)
            interval = random.uniform(1800, 3600)
            time.sleep(interval)
            
            try:
                self.rotate_listening_port()
            except Exception as e:
                logger.error(f"Failed to rotate port: {e}")
                
    def rotate_listening_port(self):
        """Change the listening port to enhance endpoint hiding"""
        # Close existing listener
        old_port = self.client_listener_port
        self.client_listener.close()
        
        # Create new listener on random port
        self.client_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_listener.bind((self.current_ip, 0))  # Bind to random port
        self.client_listener_port = self.client_listener.getsockname()[1]
        self.client_listener.listen(5)
        
        # Update server with new port
        update_packet = {
            "type": "UPDATE_PORT",
            "username": self.username,
            "new_port": self.client_listener_port
        }
        self.message_server(update_packet)
        
        # Start new listener thread
        threading.Thread(target=self.peer_listener, daemon=True).start()
        
        logger.info(f"ENDPOINT-HIDING: Rotated listening port from {old_port} to {self.client_listener_port}")
        
    def connect_to_server(self):
        """Connect to the server and start listening threads"""
        try:
            # Set socket timeout to prevent hanging connections
            self.server_socket.settimeout(10)  # 10 seconds timeout for initial connection
            
            self.server_socket.connect(self.server_address)
            self.connected = True
            logger.info(f'Connected to server at {self.server_address}')
            
            # Reset timeout for established connection
            self.server_socket.settimeout(None)
            
            # Start server listener thread
            threading.Thread(target=self.server_listener, daemon=True).start()
            signal.signal(signal.SIGINT, self.logout)
            
            return True
        except socket.error as e:
            logger.error(f'Connection error: {e}')
            return False
    
    def message_server(self, packet):
        """Send a message to the server"""
        try:
            with self.server_lock:
                msg_type = packet.get('type', 'UNKNOWN')
                logger.debug(f"NETWORK: Sending {msg_type} message to server")
                self.server_socket.send(json.dumps(packet).encode('utf-8'))
        except Exception as e:
            logger.error(f'Error sending message to server: {e}')
    
    def message_peer(self, dest_user, packet):
        """Send a message to a peer"""
        with self.peers_lock:
            retry_count = 0
            while dest_user not in self.known_peers and retry_count < 10:
                # Request address from server if not in known peers
                logger.debug(f"NETWORK: Address for {dest_user} not found, requesting from server")
                self.get_dest_address(dest_user)
                time.sleep(0.5)
                retry_count += 1
                
            if dest_user not in self.known_peers:
                raise Exception(f"Could not get address for {dest_user}")
                
            peer_ip, peer_port = self.known_peers.get(dest_user)
            
            print(f"[DEBUG] Connecting to peer {dest_user} at {peer_ip}:{peer_port}")

        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
                # Set socket timeout to prevent hanging
                peer_socket.settimeout(5)  # 5 seconds timeout
                
                peer_socket.connect((peer_ip, peer_port))
                msg_type = packet.get('type', 'UNKNOWN')
                sent = peer_socket.send(json.dumps(packet).encode('utf-8'))
                logger.debug(f'NETWORK: Sent {msg_type} to {dest_user} at {peer_ip}:{peer_port}. Bytes sent: {sent}')
                print(f"[DEBUG] Message sent successfully")

        except Exception as e:
            logger.error(f'Error sending message to peer {dest_user}: {e}')
            raise  # Re-raise to let caller handle it
    
    def run(self):
        """Main client execution loop"""
        if not self.connect_to_server():
            logger.error("Failed to connect to server. Exiting.")
            return
        
        # Start peer listener thread
        threading.Thread(target=self.peer_listener, daemon=True).start()
        
        # Authentication phase
        while not self.login_status and self.running:
            try:
                print("\n=== Secure Messenger ===")
                print("1. Login")
                print("2. Register")
                print("3. Quick login (default users)")
                print("4. Exit")
                choice = input("Select an option: ")
                
                if choice == "1":
                    username = input("Username: ")
                    password = input("Password: ")
                    
                    # Use SRP for authentication
                    self.login_srp(username, password)
                    
                    print("[DEBUG] Waiting for server response...")
                    
                    # Wait for login to complete
                    self.login_complete.wait(10)  # Wait up to 10 seconds
                    
                    if self.login_status:
                        break  # Authentication successful, break out of auth loop
                    
                elif choice == "2":
                    username = input("Username: ")
                    password = input("Password: ")
                    confirm_password = input("Confirm password: ")
                    
                    if password != confirm_password:
                        print("Passwords do not match.")
                        continue
                    
                    # Check password strength
                    if len(password) < 8:
                        print("Password must be at least 8 characters long.")
                        continue
                    
                    if not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
                        print("Password must contain uppercase letters, lowercase letters, and digits.")
                        continue
                    
                    # Check for common passwords
                    common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
                    if password.lower() in common_passwords or password.lower() in [u["password"].lower() for u in self.default_users]:
                        print("Password is too common. Please choose a stronger password.")
                        continue
                    
                    self.register_srp(username, password)
                    time.sleep(1)  # Give server time to process
                    
                elif choice == "3":
                    print("\nAvailable default users:")
                    for i, user in enumerate(self.default_users, 1):
                        print(f"{i}. {user['username']} (password: {user['password']})")
                    
                    subchoice = input("Select a user (1-3): ")
                    try:
                        idx = int(subchoice) - 1
                        if 0 <= idx < len(self.default_users):
                            user = self.default_users[idx]
                            print(f"Logging in as {user['username']}...")
                            self.login_srp(user['username'], user['password'])
                            
                            print("[DEBUG] Waiting for server response...")
                            
                            # Wait for login to complete
                            self.login_complete.wait(10)  # Wait up to 10 seconds
                            
                            if self.login_status:
                                break  # Authentication successful, break out of auth loop
                        else:
                            print("Invalid selection.")
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                
                elif choice == "4":
                    print("Exiting...")
                    self.running = False
                    return
                
                time.sleep(0.5)  # Short pause
                
            except KeyboardInterrupt:
                print("\nExiting...")
                self.running = False
                return
                
            except Exception as e:
                logger.error(f"Error in login menu: {e}")
                print(f"Error: {e}")
        
        if not self.running:
            return
        
        # Command processing phase after successful login
        if self.login_status:
            print("[DEBUG] Starting command processing")
            print("\nType 'help' to see available commands.")
            print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
            sys.stdout.flush()
            
            # Simple command loop - no new thread needed
            while self.connected and self.login_status and self.running:
                try:
                    command = input()
                    print(f"[DEBUG] Received command: '{command}'")
                    
                    if not command:
                        print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
                        sys.stdout.flush()
                        continue
                    
                    command_parts = command.split(maxsplit=2)
                    
                    if not command_parts:
                        print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
                        sys.stdout.flush()
                        continue
                    
                    if command_parts[0].lower() == 'list':
                        self.handle_list()
                    elif command_parts[0].lower() == 'help':
                        self.show_help()
                    elif command_parts[0].lower() == 'logout':
                        self.logout()
                        break
                    elif len(command_parts) >= 3 and command_parts[0].lower() == 'send':
                        destination_username = command_parts[1]
                        message = command_parts[2]
                        self.handle_send(destination_username, message)
                    else:
                        print("Invalid command. Type 'help' to see available commands.")
                    
                    print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
                    sys.stdout.flush()
                    
                except KeyboardInterrupt:
                    print("\nLogging out...")
                    self.logout()
                    break
                except Exception as e:
                    logger.error(f'Error processing command: {e}')
                    print(f"\nError: {e}")
                    print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
                    sys.stdout.flush()
    
    def solve_puzzle(self, challenge_b64, difficulty):
        """
        Solve a computational puzzle from the server
        The puzzle requires finding a value that, when hashed with the challenge,
        produces a hash with 'difficulty' number of leading zeros
        """
        print(f"Server requested a client puzzle (difficulty: {difficulty})")
        print("Solving puzzle...")
        logger.info(f"DOS-PROTECTION: Solving client puzzle with difficulty {difficulty}")
        
        try:
            challenge = base64.b64decode(challenge_b64)
            solution_found = False
            attempts = 0
            start_time = time.time()
            
            while not solution_found and attempts < 100000:  # Limit attempts
                # Generate a random solution
                solution = os.urandom(16)
                
                # Check if it produces a hash with required leading zeros
                hash_result = hashlib.sha256(challenge + solution).hexdigest()
                
                if hash_result.startswith("0" * difficulty):
                    elapsed = time.time() - start_time
                    print(f"Puzzle solved in {elapsed:.2f} seconds after {attempts} attempts")
                    logger.info(f"DOS-PROTECTION: Puzzle solved in {elapsed:.2f}s after {attempts} attempts")
                    return base64.b64encode(solution).decode('utf-8')
                
                attempts += 1
                
                # Every 1000 attempts, provide feedback
                if attempts % 1000 == 0:
                    elapsed = time.time() - start_time
                    print(f"Still solving puzzle... {attempts} attempts, {elapsed:.2f} seconds elapsed")
            
            print("Failed to solve puzzle in reasonable time")
            logger.warning("DOS-PROTECTION: Failed to solve puzzle in reasonable time")
            return None
            
        except Exception as e:
            logger.error(f"Error solving puzzle: {e}")
            return None
    
    def server_listener(self):
        """Listen for messages from the server"""
        while self.connected and self.running:
            try:
                data = self.server_socket.recv(4096)
                if not data:
                    logger.info("Server closed the connection.")
                    self.connected = False
                    print("\nConnection to server lost.")
                    break
                
                message = json.loads(data.decode('utf-8'))
                msg_type = message.get('type', 'UNKNOWN')
                logger.debug(f'NETWORK: Received {msg_type} from server')
                
                # Handle puzzle challenge
                if msg_type == 'PUZZLE_CHALLENGE':
                    challenge = message.get('puzzle')
                    difficulty = message.get('difficulty', 3)
                    
                    # Solve the puzzle
                    solution = self.solve_puzzle(challenge, difficulty)
                    
                    if solution:
                        # Resend the login request with the puzzle solution
                        if self.srp_data and "a" in self.srp_data:
                            a = self.srp_data["a"]
                            A = pow(self.srp_client.g, a, self.srp_client.N)
                            
                            packet = {
                                "type": "SRP-START",
                                "username": self.username,
                                "A": hex(A)[2:],
                                "puzzle_solution": solution
                            }
                            
                            self.message_server(packet)
                            print("Sending puzzle solution...")
                        else:
                            print("Login data not available. Please try logging in again.")
                    else:
                        print("Could not solve the puzzle. Please try again later.")
                
                elif msg_type == 'RESPONSE':
                    print(f"\n{message.get('message')}")
                    if self.login_status:
                        print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
                        sys.stdout.flush()
                elif msg_type == 'ADDRESS':
                    self.handle_address_response(message)
                elif msg_type == 'LOGIN_SUCCESS':
                    self.handle_login_success(message)
                elif msg_type == 'LOGIN_FAIL':
                    self.handle_login_fail(message)
                elif msg_type == 'REGISTER_RESPONSE':
                    self.handle_register_response(message)
                elif msg_type == 'SRP-CHALLENGE':
                    self.handle_srp_challenge(message)
                elif msg_type == 'KEY_STORE_RESPONSE':
                    logger.debug(f'NETWORK: Key store response: {message.get("message")}')
                elif msg_type == 'KEY_REQUEST_RESPONSE':
                    self.handle_key_request_response(message)
                elif msg_type == 'PORT_UPDATE_RESPONSE':
                    logger.debug(f'ENDPOINT-HIDING: Port update response: {message.get("message")}')
                else:
                    logger.warning(f'Unknown message type from server: {msg_type}')
                    
            except json.JSONDecodeError as e:
                logger.error(f'Invalid JSON from server: {e}')
            except Exception as e:
                logger.error(f'Error receiving from server: {e}')
                self.connected = False
                print(f"\nError communicating with server: {e}")
                break
    
    def peer_listener(self):
        """Listen for connections from other clients"""
        logger.info(f'NETWORK: Listening for peer connections on port {self.client_listener_port}')
        
        while self.running:
            try:
                conn, addr = self.client_listener.accept()
                logger.debug(f"NETWORK: Accepted connection from {addr}")
                threading.Thread(target=self.handle_peer_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                logger.error(f'Error accepting peer connection: {e}')
                if not self.running:
                    break
    
    def handle_peer_connection(self, conn, addr):
        """Handle a connection from another client"""
        try:
            # Set a reasonable timeout for receiving data
            conn.settimeout(5)  # 5 seconds timeout
            
            data = conn.recv(4096)
            if not data:
                return
            
            # Limit data size to prevent memory attacks
            if len(data) > 1024 * 1024:  # 1MB max
                logger.warning(f"SECURITY: Rejected oversized message ({len(data)} bytes) from {addr}")
                return
                
            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type', 'UNKNOWN')
            logger.debug(f'NETWORK: Received {msg_type} from peer {addr}')
            
            if msg_type == 'MESSAGE':
                self.handle_received_message(message, conn)
            elif msg_type == 'KEY_EXCHANGE':
                self.handle_key_exchange(message, conn)
            elif msg_type == 'KEY_EXCHANGE_RESPONSE':
                self.handle_key_exchange_response(message)
            elif msg_type == 'KEY_ROTATION':
                self.handle_key_rotation(message)
            elif msg_type == 'MESSAGE_ACK':
                logger.debug(f"NETWORK: Message acknowledged by {message.get('source_user')}")
            else:
                logger.warning(f'Unknown message type from peer: {msg_type}')
        
        except json.JSONDecodeError as e:
            logger.error(f'Invalid JSON from peer: {e}')
        except socket.timeout:
            logger.warning(f"Connection from {addr} timed out")
        except Exception as e:
            logger.error(f'Error handling peer message: {e}')
        finally:
            conn.close()
    
    def register_srp(self, username, password):
        """Register a new user account using SRP"""
        try:
            # Generate a salt
            salt = self.srp_client.generate_salt()
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            
            # Compute the verifier
            verifier = self.srp_client.compute_verifier(username, password, salt)
            verifier_hex = hex(verifier)[2:]  # Convert to hex string without '0x' prefix
            
            # Save username for later
            self.username = username
            
            # Send registration request
            packet = {
                "type": "SRP-REGISTER",
                "username": username,
                "salt": salt_b64,
                "verifier": verifier_hex
            }
            
            logger.info(f"SECURITY: Registering user {username} with SRP (verifier bit length: {verifier.bit_length()})")
            self.message_server(packet)
            print("Registration request sent. Please wait...")
            
        except Exception as e:
            logger.error(f'Error during SRP registration: {e}')
            print(f"Registration error: {e}")
            self.username = None
    
    def login_srp(self, username, password):
        """Log in using SRP protocol"""
        self.username = username  # Store username temporarily
        
        try:
            # Reset login completion event
            self.login_complete.clear()
            
            # Start SRP authentication (will get salt from server)
            # Generate client's private and public values
            a = random.randint(1, self.srp_client.N - 1)
            A = pow(self.srp_client.g, a, self.srp_client.N)
            
            logger.info(f"SRP: Initiating authentication for {username}")
            
            # Save login data for later
            self.srp_data = {
                "username": username,
                "password": password,
                "a": a
            }
            
            # Send login request
            packet = {
                "type": "SRP-START",
                "username": username,
                "A": hex(A)[2:]  # Convert to hex string without '0x' prefix
            }
            
            self.message_server(packet)
            print("Authentication in progress...")
            
        except Exception as e:
            logger.error(f'Error initiating SRP login: {e}')
            print(f"Login error: {e}")
            self.username = None
            self.srp_data = None
    
    def handle_srp_challenge(self, message):
        """Handle SRP challenge from server"""
        try:
            if not self.srp_data:
                logger.error("SRP: Data missing")
                return
                
            # Extract SRP challenge data
            salt_b64 = message.get("salt")
            B_hex = message.get("B")
            
            # Decode salt and B
            salt = base64.b64decode(salt_b64)
            B = int(B_hex, 16)
            
            logger.debug(f"SRP: Received challenge with salt and B value (B bit length: {B.bit_length()})")
            
            # Get stored login data
            username = self.srp_data["username"]
            password = self.srp_data["password"]
            a = self.srp_data["a"]
            A = pow(self.srp_client.g, a, self.srp_client.N)
            
            # Calculate x
            username_password = f"{username}:{password}".encode('utf-8')
            h_up = hashlib.sha256(username_password).digest()
            x_hash = hashlib.sha256(salt + h_up).digest()
            x = int.from_bytes(x_hash, byteorder='big')
            
            # Compute client proof and session key
            M, K = self.srp_client.compute_client_proof(username, salt, A, B, x, a)
            
            # Save verification data
            self.srp_verify = {
                "A": A,
                "M": M,
                "K": K
            }
            
            # Send SRP verification
            packet = {
                "type": "SRP-VERIFY",
                "username": username,
                "M": M.hex(),
                "reciever_port": self.client_listener_port
            }
            
            logger.debug(f"SRP: Sending verification with client proof")
            self.message_server(packet)
            
        except Exception as e:
            logger.error(f'Error in SRP challenge: {e}')
            print(f"Authentication error: {e}")
            self.username = None
            self.srp_data = None
            self.login_complete.set()  # Signal that login failed
    
    def logout(self, signum=None, frame=None):
        """Log out from the server and securely wipe keys"""
        try:
            if self.username and self.login_status:
                packet = {
                    "type": "SIGN-OUT",
                    "username": self.username
                }
                self.message_server(packet)
                logger.info(f'Logged out: {self.username}')
            
            # Securely wipe sensitive information from memory
            if hasattr(self, 'ephemeral_keys'):
                logger.info("SECURITY: Securely wiping ephemeral keys from memory")
                for username, key_data in self.ephemeral_keys.items():
                    if 'private_key' in key_data:
                        # Overwrite private key data with random bytes
                        key_data['private_key'] = os.urandom(32)
                self.ephemeral_keys.clear()
            
            if hasattr(self, 'shared_keys'):
                logger.info("SECURITY: Securely wiping shared keys from memory")
                for username, key_data in self.shared_keys.items():
                    if 'key' in key_data:
                        # Overwrite key with random data
                        key_data['key'] = os.urandom(32)
                self.shared_keys.clear()
                
        except Exception as e:
            logger.error(f"Error during logout: {e}")
        
        self.login_status = False
        self.running = False
        
        if signum is not None:  # If called as signal handler
            sys.exit(0)
    
    def handle_list(self):
        """Request list of online users from server"""
        if not self.login_status:
            print("You must be logged in to list users.")
            return
            
        packet = {
            "type": "LIST",
            "username": self.username
        }
        logger.debug("SECURITY: Requesting list of online users")
        self.message_server(packet)
    
    def handle_send(self, dest_user, message, is_dummy=False):
        """Send a message to another user with enhanced forward secrecy"""
        if not self.login_status:
            print("You must be logged in to send messages.")
            return
            
        if dest_user == self.username:
            print("You cannot send messages to yourself.")
            return
        
        # Skip UI output if it's a dummy message
        if not is_dummy:
            # Update last real message time for dummy traffic scheduling
            self.last_real_message_time = time.time()
            logger.debug(f"SECURITY: Updated last_real_message_time to {self.last_real_message_time}")
        
        # First, ensure we have a shared key with the destination
        if dest_user not in self.shared_keys:
            if not is_dummy:
                print(f"Establishing secure connection with {dest_user}...")
            try:
                if not self.establish_secure_session(dest_user):
                    if not is_dummy:
                        print(f"Could not establish secure connection with {dest_user}.")
                    return
            except Exception as e:
                if not is_dummy:
                    print(f"Error establishing secure connection: {e}")
                return
        
        # Get the shared key and message counter
        with self.keys_lock:
            key_data = self.shared_keys[dest_user]
            base_shared_key = key_data["key"]
            message_counter = key_data["messages_sent"]
            
            # Check if key rotation is needed (based on message count or time)
            key_age = int(time.time()) - key_data["timestamp"]
            
            # Rotate key after 100 messages or 10 minutes
            if message_counter >= 100 or key_age > 600:
                if not is_dummy:
                    print(f"Rotating encryption key for {dest_user}...")
                    logger.info(f"PFS: Rotating key with {dest_user} (reason: {'message count' if message_counter >= 100 else 'age'})")
                try:
                    if not self.rotate_key(dest_user):
                        if not is_dummy:
                            print(f"Could not rotate encryption key for {dest_user}.")
                        return
                    key_data = self.shared_keys[dest_user]
                    base_shared_key = key_data["key"]
                    message_counter = 0  # Reset counter after rotation
                except Exception as e:
                    if not is_dummy:
                        print(f"Error rotating key: {e}")
                    return
            
            # Derive a unique message key for forward secrecy
            message_key = self.derive_message_key(base_shared_key, message_counter)
            
            # Update message counter
            key_data["messages_sent"] += 1
            
            if not is_dummy:
                logger.info(f"SECURITY: Message to {dest_user} using PFS key for counter {message_counter}")
        
        # Encrypt the message with the message-specific key
        try:
            nonce, ciphertext = self.encrypt_message(message_key, message)
            
            # Add HMAC for message integrity
            hmac_tag = self.create_hmac(message_key, nonce + ciphertext)
            
            # Create message packet
            msg_id = str(uuid.uuid4())
            packet = {
                "type": "MESSAGE",
                "source_ip": self.current_ip,
                "source_port": self.client_listener_port,
                "source_user": self.username,
                "to": dest_user,
                "nonce": binascii.hexlify(nonce).decode('utf-8'),
                "message": binascii.hexlify(ciphertext).decode('utf-8'),
                "hmac": binascii.hexlify(hmac_tag).decode('utf-8'),
                "message_id": msg_id,
                "timestamp": int(time.time()),
                "counter": message_counter,  # Include counter for recipient to derive same key
                "is_dummy": is_dummy  # Flag for dummy messages
            }
            
            if not is_dummy:
                logger.debug(f"ENCRYPTION: Message to {dest_user} (ID: {msg_id[:8]}...) encrypted with {len(ciphertext)} bytes ciphertext")
            
            # Only store real messages in history
            if not is_dummy:
                self.store_message_history(dest_user, message, True, int(time.time()))
            
            # Send the message
            self.message_peer(dest_user, packet)
            
            if not is_dummy:
                print(f"Message sent to {dest_user}")
            
        except Exception as e:
            logger.error(f'Error sending message to {dest_user}: {e}')
            if not is_dummy:
                print(f"Error sending message: {e}")
    
    def derive_message_key(self, base_key, counter):
        """Derive a unique key for each message for perfect forward secrecy"""
        # Create a unique counter-specific info string
        info = f"message_key_{counter}".encode()
        
        logger.debug(f"PFS: Deriving message-specific key for counter {counter}")
        
        # Derive a new key for this specific message
        message_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        ).derive(base_key)
        
        message_key_hash = hashlib.sha256(message_key).hexdigest()[:8]
        logger.debug(f"PFS: Generated message-specific key (hash prefix: {message_key_hash})")
        
        return message_key
    
    def handle_received_message(self, data, conn):
        """Handle a received message from another client with enhanced security"""
        source_user = data.get("source_user")
        message_id = data.get("message_id")
        timestamp = data.get("timestamp", int(time.time()))
        is_dummy = data.get("is_dummy", False)
        counter = data.get("counter", 0)
        
        # Skip processing for dummy messages
        if is_dummy:
            logger.debug(f"ENDPOINT-HIDING: Received dummy message from {source_user}")
            # Just acknowledge it
            ack_packet = {
                "type": "MESSAGE_ACK",
                "source_user": self.username,
                "message_id": message_id
            }
            
            try:
                conn.send(json.dumps(ack_packet).encode('utf-8'))
            except:
                pass
            return
        
        # Check for message replay 
        if message_id in self.recent_message_ids:
            logger.warning(f"SECURITY: Detected message replay from {source_user} (ID: {message_id[:8]}...)")
            return
            
        # Store message ID to prevent replay 
        self.recent_message_ids.add(message_id)
        
        # Limit size of recent_message_ids (LRU-like behavior)
        if len(self.recent_message_ids) > 1000:
            # Remove oldest items
            logger.debug("SECURITY: Pruning message ID cache (> 1000 entries)")
            tmp = list(self.recent_message_ids)
            self.recent_message_ids = set(tmp[-1000:])
        
        logger.debug(f"NETWORK: Processing message from {source_user} (counter: {counter})")
        
        # Get the base shared key
        with self.keys_lock:
            if source_user not in self.shared_keys:
                logger.warning(f'SECURITY: Received message from {source_user} but no shared key exists')
                return
            
            key_data = self.shared_keys[source_user]
            base_shared_key = key_data["key"]
            
            # Check key age - request key rotation if needed
            key_age = int(time.time()) - key_data["timestamp"]
            if key_age > 600:  # 10 minutes
                logger.info(f"PFS: Key for {source_user} is old ({key_age}s), requesting rotation")
                threading.Thread(target=self.rotate_key, args=(source_user,), daemon=True).start()
            
            # Update message counter
            key_data["messages_received"] += 1
            
            # Request key rotation after 100 messages received
            if key_data["messages_received"] >= 100:
                logger.info(f"PFS: Received 100 messages from {source_user}, requesting key rotation")
                threading.Thread(target=self.rotate_key, args=(source_user,), daemon=True).start()
        
        # Derive the same message-specific key that the sender used
        message_key = self.derive_message_key(base_shared_key, counter)
        
        # Get message components
        try:
            nonce = binascii.unhexlify(data.get("nonce"))
            ciphertext = binascii.unhexlify(data.get("message"))
            received_hmac = binascii.unhexlify(data.get("hmac"))
            
            # Verify HMAC
            computed_hmac = self.create_hmac(message_key, nonce + ciphertext)
            if not hmac.compare_digest(computed_hmac, received_hmac):
                logger.warning(f'SECURITY: HMAC verification failed for message from {source_user}')
                print(f"\nReceived message with invalid integrity check from {source_user}. Message rejected.")
                print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
                sys.stdout.flush()
                return
            
            logger.debug(f"SECURITY: Message from {source_user} passed HMAC verification")
            
            # Decrypt the message (now with padding removal)
            plaintext = self.decrypt_message(message_key, nonce, ciphertext)
            logger.debug(f"ENCRYPTION: Successfully decrypted message from {source_user} ({len(ciphertext)} bytes)")
            
            # Store in message history
            self.store_message_history(source_user, plaintext, False, timestamp)
            
            # Print the message
            print(f"\n<From {source_user}> {plaintext}")
            print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
            sys.stdout.flush()
            
            # Send acknowledgement
            ack_packet = {
                "type": "MESSAGE_ACK",
                "source_user": self.username,
                "message_id": message_id
            }
            
            try:
                conn.send(json.dumps(ack_packet).encode('utf-8'))
                logger.debug(f"NETWORK: Sent acknowledgment for message {message_id[:8]}...")
            except Exception as e:
                # Cannot send acknowledgement, connection might be closed
                logger.error(f"Failed to send message acknowledgement: {e}")
                
        except Exception as e:
            logger.error(f'Error processing message from {source_user}: {e}')
            print(f"\nError processing message from {source_user}: {e}")
            print(f'{self.username}@{self.current_ip}: Enter Command>> ', end='')
            sys.stdout.flush()
    
    def establish_secure_session(self, dest_user):
        """Establish a secure session with another user using ephemeral keys"""
        print(f"\n[DEBUG] Starting key exchange with {dest_user}")
        logger.info(f"SECURITY: Starting key exchange with {dest_user}")
        
        # Generate a new ephemeral key pair
        private_key, public_key = self.generate_key_pair()
        
        # Create a unique session identifier 
        session_id = os.urandom(16).hex()
        logger.debug(f"SECURITY: Generated session ID {session_id[:8]}... for key exchange")
        
        # Use a deterministic method for both sides to generate the same auth tag
        # Sort usernames to ensure both sides compute the same tag
        users_sorted = sorted([self.username, dest_user])
        auth_data = f"{users_sorted[0]}:{users_sorted[1]}:{session_id}".encode()
        auth_tag = hmac.new(
            hashlib.sha256(auth_data).digest(),
            auth_data,
            hashlib.sha256
        ).digest()
        
        logger.debug(f"SECURITY: Generated authentication tag using sorted usernames: {users_sorted[0]}:{users_sorted[1]}")
        
        # Store our own ephemeral key (in memory only)
        with self.keys_lock:
            self.ephemeral_keys[self.username] = {
                "private_key": private_key,
                "public_key": public_key,
                "timestamp": int(time.time()),
                "session_id": session_id,
                "auth_tag": auth_tag.hex()
            }
            logger.debug("SECURITY: Stored ephemeral key pair in memory")
        
        # Serialize the public key for transmission
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create an event for key exchange
        self.key_exchange_events[dest_user] = threading.Event()
        
        # Send key exchange request
        packet = {
            "type": "KEY_EXCHANGE",
            "source_user": self.username,
            "public_key": public_key_bytes.decode('utf-8'),
            "source_ip": self.current_ip,
            "source_port": self.client_listener_port,
            "session_id": session_id,
            "auth_tag": auth_tag.hex(),
            "timestamp": int(time.time())
        }
        
        # Get destination address if not already known
        if dest_user not in self.known_peers:
            print(f"[DEBUG] Requesting address for {dest_user}")
            self.get_dest_address(dest_user)
            for attempt in range(10):  # Try up to 10 times
                time.sleep(0.5)
                if dest_user in self.known_peers:
                    print(f"[DEBUG] Got address for {dest_user}: {self.known_peers[dest_user]}")
                    break
            if dest_user not in self.known_peers:
                logger.error(f'Could not get address for {dest_user}')
                return False
        
        try:
            print(f"[DEBUG] Sending key exchange request to {dest_user}")
            self.message_peer(dest_user, packet)
            
            # Wait for key exchange to complete
            print(f"[DEBUG] Waiting for key exchange response from {dest_user}")
            success = self.key_exchange_events[dest_user].wait(10)  # Wait up to 10 seconds
            
            if not success or dest_user not in self.shared_keys:
                logger.error(f'Key exchange timed out with {dest_user}')
                return False
            
            logger.info(f"SECURITY: Successfully established secure session with {dest_user}")
            return True
            
        except Exception as e:
            logger.error(f'Error in key exchange with {dest_user}: {e}')
            return False
    
    def handle_key_exchange(self, data, conn):
        """Handle a key exchange request from another client"""
        source_user = data.get("source_user")
        sender_pub_key_pem = data.get("public_key").encode('utf-8')
        sender_ip = data.get("source_ip")
        sender_port = data.get("source_port")
        
        # Check if enhanced protocol fields are present
        enhanced = 'session_id' in data and 'auth_tag' in data and 'timestamp' in data
        
        if enhanced:
            session_id = data.get("session_id")
            auth_tag_hex = data.get("auth_tag")
            timestamp = data.get("timestamp", 0)
            
            # Verify timestamp is recent
            current_time = int(time.time())
            if current_time - timestamp > 60:  # Stale key exchange (>60 seconds old)
                logger.warning(f"SECURITY: Rejected stale key exchange from {source_user} (age: {current_time-timestamp}s)")
                return
                
            # Verify auth tag using same deterministic method as sender
            users_sorted = sorted([source_user, self.username])
            auth_data = f"{users_sorted[0]}:{users_sorted[1]}:{session_id}".encode()
            expected_auth_tag = hmac.new(
                hashlib.sha256(auth_data).digest(),
                auth_data,
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(bytes.fromhex(auth_tag_hex), expected_auth_tag):
                logger.warning(f"SECURITY: Authentication tag verification failed for {source_user}")
                return
            
            logger.debug(f"SECURITY: Authenticated key exchange request from {source_user} (session: {session_id[:8]}...)")
        
        print(f"[DEBUG] Received key exchange request from {source_user}")
        
        # Add the peer to known peers
        with self.peers_lock:
            self.known_peers[source_user] = (sender_ip, sender_port)
            print(f"[DEBUG] Added {source_user} to known peers: {sender_ip}:{sender_port}")
            logger.debug(f"NETWORK: Added {source_user} to known peers: {sender_ip}:{sender_port}")
        
        try:
            # Load the peer's public key
            peer_pub_key = serialization.load_pem_public_key(
                sender_pub_key_pem,
                backend=default_backend()
            )
            
            # Generate our own key pair
            private_key, public_key = self.generate_key_pair()
            
            # Store our ephemeral key
            with self.keys_lock:
                if enhanced:
                    # Create our own session ID and auth tag using the same deterministic method
                    our_session_id = os.urandom(16).hex()
                    users_sorted = sorted([self.username, source_user])
                    our_auth_data = f"{users_sorted[0]}:{users_sorted[1]}:{our_session_id}".encode()
                    our_auth_tag = hmac.new(
                        hashlib.sha256(our_auth_data).digest(),
                        our_auth_data,
                        hashlib.sha256
                    ).digest()
                    
                    self.ephemeral_keys[self.username] = {
                        "private_key": private_key,
                        "public_key": public_key,
                        "timestamp": int(time.time()),
                        "session_id": our_session_id,
                        "auth_tag": our_auth_tag.hex()
                    }
                    logger.debug(f"SECURITY: Created new session ID {our_session_id[:8]}... for response")
                else:
                    self.ephemeral_keys[self.username] = {
                        "private_key": private_key,
                        "public_key": public_key,
                        "timestamp": int(time.time())
                    }
            
            # Serialize our public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Generate shared key
            shared_key = self.generate_shared_session_key(
                private_key, 
                peer_pub_key, 
                source_user
            )
            
            # Prepare response using same format as request
            if enhanced:
                response = {
                    "type": "KEY_EXCHANGE_RESPONSE",
                    "source_user": self.username,
                    "public_key": public_key_bytes.decode('utf-8'),
                    "session_id": our_session_id,
                    "auth_tag": our_auth_tag.hex(),
                    "timestamp": int(time.time()),
                    "original_session_id": session_id
                }
            else:
                # Legacy format
                response = {
                    "type": "KEY_EXCHANGE_RESPONSE",
                    "source_user": self.username,
                    "public_key": public_key_bytes.decode('utf-8')
                }
            
            # Send response
            try:
                print(f"[DEBUG] Opening new connection to {source_user} at {sender_ip}:{sender_port}")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as response_socket:
                    response_socket.connect((sender_ip, sender_port))
                    response_socket.send(json.dumps(response).encode('utf-8'))
                    print(f"[DEBUG] Key exchange response sent via new connection")
                    logger.debug(f"NETWORK: Key exchange response sent to {source_user} via new connection")
            except Exception as e:
                print(f"[DEBUG] Error sending response via new connection: {e}")
                # Fall back to the original connection as a last resort
                conn.send(json.dumps(response).encode('utf-8'))
                print(f"[DEBUG] Key exchange response sent via original connection")
                logger.debug(f"NETWORK: Key exchange response sent via original connection (fallback)")
                
        except Exception as e:
            print(f"[DEBUG] Error handling key exchange from {source_user}: {e}")
            logger.error(f'Error handling key exchange from {source_user}: {e}')
    
    def handle_key_exchange_response(self, data):
        """Handle a response to our key exchange request"""
        source_user = data.get("source_user")
        peer_pub_key_pem = data.get("public_key").encode('utf-8')
        
        # Check for enhanced protocol fields
        enhanced = 'session_id' in data and 'auth_tag' in data and 'timestamp' in data
        
        if enhanced:
            session_id = data.get("session_id")
            auth_tag_hex = data.get("auth_tag")
            original_session_id = data.get("original_session_id")
            timestamp = data.get("timestamp", 0)
            
            # Verify timestamp
            current_time = int(time.time())
            if current_time - timestamp > 60:  # Stale key exchange (>60 seconds old)
                logger.warning(f"SECURITY: Rejected stale key exchange response (age: {current_time-timestamp}s)")
                return
                
            # Verify this is a response to our request
            with self.keys_lock:
                if self.username not in self.ephemeral_keys:
                    logger.error(f'SECURITY: No ephemeral key found for ourselves during key exchange with {source_user}')
                    return
                    
                our_data = self.ephemeral_keys[self.username]
                if 'session_id' in our_data and our_data['session_id'] != original_session_id:
                    logger.warning(f"SECURITY: Session ID mismatch in key exchange response from {source_user}")
                    logger.warning(f"Expected {our_data['session_id'][:8]}..., got {original_session_id[:8]}...")
                    return
                
                logger.debug(f"SECURITY: Verified session ID match ({original_session_id[:8]}...)")
                
            # Verify auth tag
            users_sorted = sorted([source_user, self.username])
            auth_data = f"{users_sorted[0]}:{users_sorted[1]}:{session_id}".encode()
            expected_auth_tag = hmac.new(
                hashlib.sha256(auth_data).digest(),
                auth_data,
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(bytes.fromhex(auth_tag_hex), expected_auth_tag):
                logger.warning(f"SECURITY: Authentication tag verification failed for {source_user}")
                return
            
            logger.debug(f"SECURITY: Authentication tag verified for response from {source_user}")
        else:
            logger.debug(f"SECURITY: Received legacy (non-enhanced) key exchange response from {source_user}")
        
        try:
            # Load the peer's public key
            peer_pub_key = serialization.load_pem_public_key(
                peer_pub_key_pem,
                backend=default_backend()
            )
            
            # Get our private key
            with self.keys_lock:
                if self.username not in self.ephemeral_keys:
                    logger.error(f'No ephemeral key found for ourselves during key exchange with {source_user}')
                    return
                    
                our_private_key = self.ephemeral_keys[self.username]["private_key"]
            
            # Generate shared key
            shared_key = self.generate_shared_session_key(
                our_private_key,
                peer_pub_key,
                source_user
            )
            
            # Signal that key exchange is complete
            if source_user in self.key_exchange_events:
                self.key_exchange_events[source_user].set()
                logger.debug(f"SECURITY: Signaled completion of key exchange with {source_user}")
                
        except Exception as e:
            logger.error(f'Error handling key exchange response from {source_user}: {e}')
    
    def rotate_key(self, peer_username):
        """Rotate the encryption key for a peer"""
        logger.info(f"PFS: Initiating key rotation with {peer_username}")
        
        # Generate a new ephemeral key pair
        private_key, public_key = self.generate_key_pair()
        
        # Generate a session ID and authentication tag for key rotation
        session_id = os.urandom(16).hex()
        users_sorted = sorted([self.username, peer_username])
        auth_data = f"{users_sorted[0]}:{users_sorted[1]}:{session_id}".encode()
        auth_tag = hmac.new(
            hashlib.sha256(auth_data).digest(),
            auth_data,
            hashlib.sha256
        ).digest()
        
        # Store our new ephemeral key
        with self.keys_lock:
            self.ephemeral_keys[self.username] = {
                "private_key": private_key,
                "public_key": public_key,
                "timestamp": int(time.time()),
                "session_id": session_id,
                "auth_tag": auth_tag.hex()
            }
        
        # Serialize the public key for transmission
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create an event for key rotation
        self.key_exchange_events[peer_username] = threading.Event()
        
        # Send key rotation message with enhanced security
        packet = {
            "type": "KEY_ROTATION",
            "source_user": self.username,
            "public_key": public_key_bytes.decode('utf-8'),
            "session_id": session_id,
            "auth_tag": auth_tag.hex(),
            "timestamp": int(time.time())
        }
        
        try:
            logger.debug(f"PFS: Sending key rotation request to {peer_username}")
            self.message_peer(peer_username, packet)
            
            # Wait for key exchange to complete
            success = self.key_exchange_events[peer_username].wait(10)
            
            if not success:
                logger.error(f'PFS: Key rotation timed out with {peer_username}')
                return False
            
            logger.info(f"PFS: Successfully rotated keys with {peer_username}")
            return True
            
        except Exception as e:
            logger.error(f'Error in key rotation with {peer_username}: {e}')
            return False
    
    def handle_key_rotation(self, data):
        """Handle a key rotation message from a peer"""
        source_user = data.get("source_user")
        peer_pub_key_pem = data.get("public_key").encode('utf-8')
        
        # Check for enhanced protocol fields
        enhanced = 'session_id' in data and 'auth_tag' in data and 'timestamp' in data
        
        if enhanced:
            session_id = data.get("session_id")
            auth_tag_hex = data.get("auth_tag")
            timestamp = data.get("timestamp", 0)
            
            # Verify timestamp
            current_time = int(time.time())
            if current_time - timestamp > 60:  # Stale key rotation (>60 seconds old)
                logger.warning(f"SECURITY: Rejected stale key rotation from {source_user} (age: {current_time-timestamp}s)")
                return
                
            # Verify auth tag
            users_sorted = sorted([source_user, self.username])
            auth_data = f"{users_sorted[0]}:{users_sorted[1]}:{session_id}".encode()
            expected_auth_tag = hmac.new(
                hashlib.sha256(auth_data).digest(),
                auth_data,
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(bytes.fromhex(auth_tag_hex), expected_auth_tag):
                logger.warning(f"SECURITY: Authentication tag verification failed for key rotation from {source_user}")
                return
            
            logger.debug(f"SECURITY: Authentication tag verified for key rotation from {source_user}")
        
        logger.info(f"PFS: Received key rotation request from {source_user}")
        
        try:
            # Load the peer's public key
            peer_pub_key = serialization.load_pem_public_key(
                peer_pub_key_pem,
                backend=default_backend()
            )
            
            # Generate our own new key pair
            private_key, public_key = self.generate_key_pair()
            
            # Store our new ephemeral key
            with self.keys_lock:
                if enhanced:
                    # Create our own session ID and auth tag
                    our_session_id = os.urandom(16).hex()
                    users_sorted = sorted([self.username, source_user])
                    our_auth_data = f"{users_sorted[0]}:{users_sorted[1]}:{our_session_id}".encode()
                    our_auth_tag = hmac.new(
                        hashlib.sha256(our_auth_data).digest(),
                        our_auth_data,
                        hashlib.sha256
                    ).digest()
                    
                    self.ephemeral_keys[self.username] = {
                        "private_key": private_key,
                        "public_key": public_key,
                        "timestamp": int(time.time()),
                        "session_id": our_session_id,
                        "auth_tag": our_auth_tag.hex()
                    }
                else:
                    self.ephemeral_keys[self.username] = {
                        "private_key": private_key,
                        "public_key": public_key,
                        "timestamp": int(time.time())
                    }
            
            # Serialize our public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Generate new shared key
            self.generate_shared_session_key(
                private_key, 
                peer_pub_key, 
                source_user
            )
            
            # Prepare response based on request format
            if enhanced:
                response = {
                    "type": "KEY_EXCHANGE_RESPONSE",
                    "source_user": self.username,
                    "public_key": public_key_bytes.decode('utf-8'),
                    "session_id": our_session_id,
                    "auth_tag": our_auth_tag.hex(),
                    "timestamp": int(time.time()),
                    "original_session_id": session_id
                }
            else:
                response = {
                    "type": "KEY_EXCHANGE_RESPONSE",
                    "source_user": self.username,
                    "public_key": public_key_bytes.decode('utf-8')
                }
            
            # Send response
            logger.debug(f"PFS: Sending key rotation response to {source_user}")
            self.message_peer(source_user, response)
            
        except Exception as e:
            logger.error(f'Error handling key rotation from {source_user}: {e}')
    
    def handle_login_success(self, message):
        """Handle successful login"""
        print("\n[DEBUG] Login success received")
        self.login_status = True
        
        print(f"\n{message.get('message')}")
        
        # Verify server proof if using SRP
        if "HAMK" in message and hasattr(self, 'srp_verify'):
            HAMK = bytes.fromhex(message.get("HAMK"))
            
            # Verify the server's proof
            if not self.srp_client.verify_server_proof(
                self.srp_verify["A"],
                self.srp_verify["M"],
                self.srp_verify["K"],
                HAMK
            ):
                logger.warning("SECURITY: Server proof verification failed - potential MITM attack!")
                print("\nWARNING: Server authentication failed. The server might be compromised.")
                
                self.login_status = False
                self.login_complete.set()
                return
                
            # We now have mutual authentication with the server
            logger.info("SECURITY: Server authentication successful (mutual authentication).")
            
            # If we have a session key, we could use it for secure communications
            if "session_key" in message:
                session_key_hex = message.get("session_key")
                session_key = bytes.fromhex(session_key_hex)
                
                # Verify the session key matches our computed key
                if not hmac.compare_digest(self.srp_verify["K"], session_key):
                    logger.warning("SECURITY: Session key verification failed")
                
            # Clear SRP verification data
            delattr(self, 'srp_verify')
        
        if hasattr(self, 'srp_data'):
            delattr(self, 'srp_data')
        
        # Generate and store new ephemeral key pair
        private_key, public_key = self.generate_key_pair()
        logger.debug("SECURITY: Generated new ephemeral key pair after login")
        
        with self.keys_lock:
            self.ephemeral_keys[self.username] = {
                "private_key": private_key,
                "public_key": public_key,
                "timestamp": int(time.time())
            }
        
        # Store the public key on the server (not locally)
        logger.info(f'SECURITY: Storing ephemeral public key for {self.username}')
        self.store_ephemeral_key(public_key)
        
        # Set the last real message time
        self.last_real_message_time = time.time()
        
        # Signal that login is complete
        self.login_complete.set()
    
    def handle_login_fail(self, message):
        """Handle failed login"""
        self.login_status = False
        temp_username = self.username  # Store temporarily for the error message
        self.username = None
        
        print(f"\n{message.get('message')}")
        logger.warning(f"SECURITY: Login failed for {temp_username}: {message.get('message')}")
        
        # Clean up SRP data
        if hasattr(self, 'srp_data'):
            delattr(self, 'srp_data')
        if hasattr(self, 'srp_verify'):
            delattr(self, 'srp_verify')
        
        # Signal that login attempt is complete
        self.login_complete.set()
    
    def handle_register_response(self, message):
        """Handle registration response"""
        success = message.get("success", False)
        temp_username = self.username  # Store temporarily
        
        if not self.login_status:
            self.username = None  # Clear username if not logged in
        
        if success:
            print(f"\nUser {temp_username} registered successfully")
            logger.info(f"SECURITY: User {temp_username} registered successfully")
        else:
            print(f"\nRegistration failed: {message.get('message')}")
            logger.warning(f"SECURITY: Registration failed for {temp_username}: {message.get('message')}")
    
    def handle_address_response(self, message):
        """Handle response to address request with enhanced security"""
        requested_user = message.get("requested_user_username")
        ip = message.get("requested_user_ip")
        port = message.get("requested_user_listener_port")
        
        # Get authorization token and timestamp if present (enhanced protocol)
        auth_token = message.get("authorization_token", "")
        timestamp = message.get("timestamp", 0)
        
        # Verify timestamp is recent if provided
        if timestamp > 0:
            current_time = int(time.time())
            if current_time - timestamp > 300:  # Address is valid for 5 minutes
                logger.warning(f"ENDPOINT-HIDING: Received stale address information for {requested_user} (age: {current_time-timestamp}s)")
                return
            
            logger.debug(f"ENDPOINT-HIDING: Received fresh address for {requested_user} (age: {current_time-timestamp}s)")
        
        with self.peers_lock:
            self.known_peers[requested_user] = (ip, port)
            
            # Store the authorization token if provided
            if auth_token:
                if not hasattr(self, 'auth_tokens'):
                    self.auth_tokens = {}
                self.auth_tokens[requested_user] = auth_token
                logger.debug(f"ENDPOINT-HIDING: Stored authorization token for {requested_user}")
            
            logger.debug(f'ENDPOINT-HIDING: Added {requested_user} to known peers: {ip}:{port}')
    
    def handle_key_request_response(self, message):
        """Handle response to a key request"""
        success = message.get("success", False)
        if not success:
            logger.warning(f'SECURITY: Key request failed: {message.get("message")}')
            return
            
        username = message.get("user")
        public_key_pem = message.get("public_key")
        timestamp = message.get("timestamp")
        expiry = message.get("expiry")
        
        try:
            # Load the public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Calculate key fingerprint for logging
            fingerprint = hashlib.sha256(
                public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).hexdigest()[:8]
            
            logger.info(f'SECURITY: Received public key for {username} (fingerprint: {fingerprint})')
            
        except Exception as e:
            logger.error(f'Error processing key request response: {e}')
    
    def get_dest_address(self, dest_user):
        """Get the address of a destination user from the server"""
        if not self.login_status:
            logger.warning("SECURITY: Cannot request address: Not logged in")
            return
            
        packet = {
            "type": "ADDRESS_REQUEST",
            "source_user": self.username,
            "requested_user": dest_user
        }
        logger.debug(f"ENDPOINT-HIDING: Requesting address of {dest_user} from server")
        self.message_server(packet)
    
    def store_ephemeral_key(self, public_key):
        """Store our ephemeral public key on the server (not locally)"""
        if not self.login_status:
            logger.warning("SECURITY: Cannot store key: Not logged in")
            return
            
        # Serialize the public key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Calculate key fingerprint for logging
        fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:8]
        logger.debug(f"SECURITY: Storing ephemeral public key on server (fingerprint: {fingerprint})")
        
        # Create packet
        packet = {
            "type": "KEY_STORE",
            "username": self.username,
            "public_key": public_key_bytes.decode('utf-8'),
            "expiry": int(time.time()) + 86400  # 24 hours expiry
        }
        
        self.message_server(packet)
    
    def store_message_history(self, peer_username, message, outbound, timestamp):
        """Store a message in the history with encryption"""
        if peer_username not in self.message_history:
            self.message_history[peer_username] = []
            
        self.message_history[peer_username].append({
            "timestamp": timestamp,
            "sender": self.username if outbound else peer_username,
            "message": message,
            "outbound": outbound
        })
        
        # Save to file with encryption
        try:
            history_file = os.path.join(self.data_dir, f"history_{self.username}_{peer_username}.dat")
            
            # Encrypt message history before saving
            history_data = json.dumps(self.message_history[peer_username]).encode('utf-8')
            
            # Derive key from username and peer_username for encryption
            key_material = f"{self.username}:{peer_username}".encode('utf-8')
            key = hashlib.sha256(key_material).digest()
            
            # Encrypt with AES-GCM
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, history_data, None)
            
            # Write nonce + ciphertext to file
            with open(history_file, 'wb') as f:
                f.write(nonce + ciphertext)
                
            logger.debug(f"SECURITY: Encrypted and saved message history with {peer_username} ({len(history_data)} bytes)")
                
        except Exception as e:
            logger.error(f'Error saving message history: {e}')
    
    def show_help(self):
        """Show help information"""
        print("\n=== Secure Messenger Help ===")
        print("Available commands:")
        print("  list                    - List all online users")
        print("  send <username> <msg>   - Send a message to a user")
        print("  help                    - Show this help message")
        print("  logout                  - Log out and exit")
    
    def generate_key_pair(self):
        """Generate an EC key pair"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # Calculate key fingerprint for logging
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(public_bytes).hexdigest()[:8]
        
        logger.debug(f"SECURITY: Generated new EC key pair (public key fingerprint: {fingerprint})")
        return private_key, public_key
    
    def generate_shared_session_key(self, private_key, peer_public_key, peer_username):
        """Generate a shared session key using ECDH with consistent derivation"""
        # Get the raw shared key using ECDH
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Create a consistent salt based on the usernames (always use same order)
        usernames = sorted([self.username, peer_username])
        salt = f"{usernames[0]}:{usernames[1]}".encode()
        
        logger.debug(f"KEYGEN: Using salt '{salt.decode()}' for key derivation with {peer_username}")
        
        # Derive a symmetric key using HKDF with consistent parameters
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,  # Use sorted usernames as salt
            info=b'secure_messenger_v1',  # Consistent info
            backend=default_backend()
        ).derive(shared_key)
        
        derived_key_hash = hashlib.sha256(derived_key).hexdigest()[:8]  # First 8 chars of hash
        logger.info(f"KEYGEN: Generated shared key with {peer_username} (hash prefix: {derived_key_hash})")
        
        # Store the shared key
        with self.keys_lock:
            self.shared_keys[peer_username] = {
                "key": derived_key,
                "timestamp": int(time.time()),
                "messages_sent": 0,
                "messages_received": 0
            }
        
        return derived_key
    
    def encrypt_message(self, shared_key, plaintext):
        """Encrypt a message using AES-GCM with padding to prevent traffic analysis"""
        # Generate random padding to disguise message length
        padding_length = random.randint(10, 50)
        padding = os.urandom(padding_length)
        
        # Format: [original_length (4 bytes)][original_message][padding]
        plaintext_bytes = plaintext.encode('utf-8')
        padded_data = len(plaintext_bytes).to_bytes(4, byteorder='big') + plaintext_bytes + padding
        
        logger.debug(f"ENCRYPTION: Added {padding_length} bytes of padding to message " +
                    f"(original: {len(plaintext_bytes)} bytes, padded: {len(padded_data)} bytes)")
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, padded_data, None)
        
        logger.debug(f"ENCRYPTION: Encrypted message (ciphertext: {len(ciphertext)} bytes)")
        return nonce, ciphertext
    
    def decrypt_message(self, shared_key, nonce, ciphertext):
        """Decrypt a message using AES-GCM and remove padding"""
        aesgcm = AESGCM(shared_key)
        padded_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Extract original message length
        original_length = int.from_bytes(padded_data[:4], byteorder='big')
        
        # Extract original message
        original_message = padded_data[4:4+original_length]
        
        padding_length = len(padded_data) - 4 - original_length
        logger.debug(f"ENCRYPTION: Decrypted message and removed {padding_length} bytes of padding")
        
        return original_message.decode('utf-8')
    
    def create_hmac(self, key, data):
        """Create an HMAC for data integrity verification"""
        # Use the standard library hmac module
        h = hmac.new(key, digestmod=hashlib.sha256)
        h.update(data)
        hmac_result = h.digest()
        hmac_hash = h.hexdigest()[:8]  # First 8 chars for logging
        
        logger.debug(f"SECURITY: Generated HMAC for data (hash prefix: {hmac_hash})")
        return hmac_result

def main():
    parser = argparse.ArgumentParser(description="Secure Messenger Client")
    parser.add_argument('-sip', '--server-ip', default='127.0.0.1', help='Server IP address')
    parser.add_argument('-sp', '--server-port', type=int, default=50005, help='Server port')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    try:
        client = Client(args.server_ip, args.server_port, args.debug)
        client.run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
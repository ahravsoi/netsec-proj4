import socket
import json
import argparse
import threading
import os
import binascii
import time
import base64
import logging
import hashlib
import secrets
import random
import hmac  # Use standard library hmac for compare_digest
from typing import Dict, Tuple, Optional, List, Any

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("server")

class SRPServer:
    """Implements SRP (Secure Remote Password) protocol for the server"""
    
    def __init__(self):
        # SRP parameters
        # N = Large safe prime (RFC 5054 Group 2, 1024-bit)
        self.N = 0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73
        self.g = 2  # Generator
        self.k = 3  # Multiplier parameter (k=3 for SRP-6a)
        
    def generate_salt(self) -> bytes:
        """Generate a random salt"""
        salt = secrets.token_bytes(16)
        logger.debug(f"SRP: Generated 16-byte salt: {salt.hex()[:8]}...")
        return salt
    
    def compute_verifier(self, username: str, password: str, salt: bytes) -> int:
        """Compute the password verifier v = g^x % N"""
        # Calculate x = H(salt | H(username | ":" | password))
        username_password = f"{username}:{password}".encode('utf-8')
        h_up = hashlib.sha256(username_password).digest()
        x_hash = hashlib.sha256(salt + h_up).digest()
        x = int.from_bytes(x_hash, byteorder='big')
        
        # Calculate v = g^x % N
        v = pow(self.g, x, self.N)
        logger.debug(f"SRP: Computed verifier for {username} (bit length: {v.bit_length()})")
        return v
    
    def generate_server_credentials(self, username: str, v: int) -> Tuple[int, int]:
        """Generate server's ephemeral values for the SRP exchange"""
        # Generate server private value
        b = random.randint(1, self.N - 1)
        
        # Calculate server public value: B = (k*v + g^b) % N
        B = (self.k * v + pow(self.g, b, self.N)) % self.N
        
        logger.debug(f"SRP: Generated server credentials for {username} (B bit length: {B.bit_length()})")
        return b, B
    
    def verify_client_proof(self, username: str, salt: bytes, A: int, B: int, 
                           client_M: bytes, v: int, server_private: int) -> Optional[Tuple[bytes, bytes]]:
        """
        Verify the client's proof and generate server proof if valid
        Returns (server_proof, session_key) if verification succeeds, None otherwise
        """
        try:
            # Calculate u = H(A | B)
            u_hash = hashlib.sha256(str(A).encode() + str(B).encode()).digest()
            u = int.from_bytes(u_hash, byteorder='big')
            
            # Calculate session key: S = (A * v^u) ^ b % N
            S = pow(A * pow(v, u, self.N) % self.N, server_private, self.N)
            S_bytes = S.to_bytes((S.bit_length() + 7) // 8, byteorder='big')
            K = hashlib.sha256(S_bytes).digest()
            
            # Calculate expected client proof: M = H(H(N) XOR H(g) | H(username) | salt | A | B | K)
            h_N = hashlib.sha256(str(self.N).encode()).digest()
            h_g = hashlib.sha256(str(self.g).encode()).digest()
            h_I = hashlib.sha256(username.encode()).digest()
            
            # XOR h_N and h_g
            h_Ng = bytes(a ^ b for a, b in zip(h_N, h_g))
            
            # Combine all parts
            M_parts = h_Ng + h_I + salt + str(A).encode() + str(B).encode() + K
            expected_M = hashlib.sha256(M_parts).digest()
            
            # Verify client proof using constant-time comparison
            if not hmac.compare_digest(expected_M, client_M):
                logger.warning(f"SRP: Client proof verification failed for {username}")
                return None
            
            # Generate server proof: H(A | M | K)
            HAMK = hashlib.sha256(str(A).encode() + client_M + K).digest()
            
            # Hash the session key for logging (don't log the actual key)
            K_hash = hashlib.sha256(K).hexdigest()[:8]
            logger.debug(f"SRP: Generated server proof and session key for {username} (key hash: {K_hash})")
            
            return HAMK, K
        except Exception as e:
            logger.error(f"Error in verify_client_proof: {e}")
            return None


class Server:
    def __init__(self, port, ip, data_dir="./data"):
        """Initialize the server with the given port and IP address"""
        self.ip = ip
        self.port = port
        self.data_dir = data_dir
        
        # Ensure data directory exists
        os.makedirs(data_dir, exist_ok=True)
        
        # Separation of sensitive data
        self.auth_dir = os.path.join(data_dir, "auth")
        self.keys_dir = os.path.join(data_dir, "keys")
        os.makedirs(self.auth_dir, exist_ok=True)
        os.makedirs(self.keys_dir, exist_ok=True)
        
        # Set restrictive permissions
        try:
            os.chmod(self.auth_dir, 0o700)  # Only owner can read/write/execute
            os.chmod(self.keys_dir, 0o700)  # Only owner can read/write/execute
            os.chmod(data_dir, 0o700)       # Protect the parent directory too
            logger.debug(f"SECURITY: Set 0o700 permissions on data directories")
        except Exception as e:
            logger.warning(f"Could not set permissions on data directories: {e}")
        
        # Set up socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Enable address reuse to avoid "address already in use" errors
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)  # Can handle 5 clients at a time
        logger.info(f'Server started on {self.ip}:{self.port}')
        
        # User credentials and key storage
        self.credentials_file = os.path.join(self.auth_dir, "credentials.json")
        self.ephemeral_keys_file = os.path.join(self.keys_dir, "ephemeral_keys.json")
        
        # Initialize default users (will be added if they don't exist)
        self.default_users = {
            "alice": "password1",
            "bob": "password2",
            "charlie": "password3"
        }
        
        self.srp_server = SRPServer()
        
        # Load or initialize credentials
        self.credentials = self._load_credentials()
        
        # Ensure default users are created
        self._create_default_users()
        
        # Active users and their connections
        self.active_users = {}  # Map of {username: (connection, address, receiver_port, last_activity)}
        self.ephemeral_keys = {}  # Map of {username: {"public_key": key, "timestamp": time, "expiry": time}}
        
        # SRP sessions
        self.srp_sessions = {}  # For tracking SRP authentication sessions
        
        # Locks for thread safety
        self.users_lock = threading.Lock()
        self.keys_lock = threading.Lock()
        self.puzzle_lock = threading.Lock()
        self.username_attempt_lock = threading.Lock()
        
        # Password hasher for secure authentication and storage (fallback)
        self.password_hasher = PasswordHasher(
            time_cost=3,      # Number of iterations
            memory_cost=65536,  # 64MB in KiB
            parallelism=4,     # Number of parallel threads
            hash_len=32,       # Length of the hash
            salt_len=16        # Length of the salt
        )
        
        # Rate limiting for authentication attempts
        self.auth_attempts = {}  # Map of {ip_address: (num_attempts, last_attempt_time)}
        self.auth_lock = threading.Lock()
        
        # DoS protection parameters
        self.max_conn_per_ip = 5
        self.active_connections = {}  # Map of {ip_address: count}
        self.conn_lock = threading.Lock()
        
        # For client puzzles
        self.puzzles = {}  # Map of {username: {"challenge": bytes, "difficulty": int, "timestamp": float, "solved": bool}}
        
        # For tracking last login attempt time (timing attack prevention)
        self.last_username_attempt = {}
        
        # Connection rate limiting
        self.connection_tracker = {}  # {ip: {"count": int, "timestamp": int}}
        self.connection_tracker_lock = threading.Lock()
        
        # Load previously stored ephemeral keys
        with self.keys_lock:
            try:
                if os.path.exists(self.ephemeral_keys_file):
                    with open(self.ephemeral_keys_file, 'r') as f:
                        data = f.read()
                        self.ephemeral_keys = self._decrypt_data(data)
                        logger.info(f"SECURITY: Loaded {len(self.ephemeral_keys)} ephemeral keys from storage")
            except Exception as e:
                logger.error(f"Error loading ephemeral keys: {e}")
                self.ephemeral_keys = {}
        
        # Start a cleanup thread to remove inactive users
        threading.Thread(target=self._cleanup_inactive_users, daemon=True).start()
        
        # Start a thread to expire old puzzles and tokens
        threading.Thread(target=self._cleanup_server_state, daemon=True).start()

    def _encrypt_data(self, data):
        """Encrypt data before saving to file"""
        # Generate a key derivation from a server secret
        server_secret = os.environ.get('SERVER_SECRET', 'super_secret_value')
        salt = b'secure_messenger_salt'
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'file_encryption',
            backend=default_backend()
        )
        key = kdf.derive(server_secret.encode())
        
        # Encrypt with AES-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        plaintext = json.dumps(data).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Return nonce + ciphertext
        logger.debug(f"SECURITY: Encrypted data for storage ({len(plaintext)} bytes → {len(nonce + ciphertext)} bytes)")
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def _decrypt_data(self, encrypted_data):
        """Decrypt data from file"""
        if not encrypted_data:
            return {}
            
        # Generate the same key
        server_secret = os.environ.get('SERVER_SECRET', 'super_secret_value')
        salt = b'secure_messenger_salt'
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'file_encryption',
            backend=default_backend()
        )
        key = kdf.derive(server_secret.encode())
        
        # Decrypt
        try:
            data = base64.b64decode(encrypted_data)
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            logger.debug(f"SECURITY: Successfully decrypted data from storage ({len(data)} bytes)")
            return json.loads(plaintext)
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            # Try legacy format as fallback
            try:
                # If we can't decrypt, assume it's in the old format
                logger.warning("SECURITY: Falling back to legacy (unencrypted) data format")
                return json.loads(encrypted_data) 
            except:
                return {}
        
    def _load_credentials(self) -> Dict[str, Dict[str, Any]]:
        """Load user credentials from file or create with defaults if not exists"""
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, 'r') as f:
                    encrypted_data = f.read()
                    creds = self._decrypt_data(encrypted_data)
                    logger.info(f"SECURITY: Loaded {len(creds)} user credentials from encrypted storage")
                    return creds
            except Exception as e:
                logger.error(f"Error loading credentials: {e}")
                # Try legacy format as fallback
                try:
                    with open(self.credentials_file, 'r') as f:
                        return json.load(f)
                except:
                    return {}
        
        # No credentials file yet
        logger.info("SECURITY: No credentials file found, starting with empty credentials")
        return {}
    
    def _save_credentials(self) -> None:
        """Save user credentials to file (encrypted)"""
        with open(self.credentials_file, 'w') as f:
            encrypted_data = self._encrypt_data(self.credentials)
            f.write(encrypted_data)
            logger.debug(f"SECURITY: Saved encrypted credentials for {len(self.credentials)} users")
    
    def _create_default_users(self) -> None:
        """Create default users if they don't exist (with enhanced security)"""
        created_users = []
        for username, password in self.default_users.items():
            if username not in self.credentials:
                try:
                    # Generate salt
                    salt = self.srp_server.generate_salt()
                    salt_b64 = base64.b64encode(salt).decode('utf-8')
                    
                    # Compute verifier
                    verifier = self.srp_server.compute_verifier(username, password, salt)
                    verifier_hex = hex(verifier)[2:]  # Convert to hex string without '0x' prefix
                    
                    # Store the SRP registration data
                    self.credentials[username] = {
                        "salt": salt_b64,
                        "verifier": verifier_hex,
                        "registration_time": int(time.time()),
                        "user_id": secrets.token_hex(16),  # Unique identifier
                        "failed_attempts": 0,  # Track failed login attempts
                        "last_failed_login": 0  # Track timing of last failed login
                    }
                    
                    created_users.append(username)
                    logger.debug(f"SECURITY: Created default user {username} with SRP verifier (bit length: {verifier.bit_length()})")
                    
                except Exception as e:
                    logger.error(f"Error creating default user {username}: {e}")
        
        if created_users:
            # Save all created users
            self._save_credentials()
            logger.info(f"Created default users: {', '.join(created_users)}")
            
    def _cleanup_inactive_users(self) -> None:
        """Remove users who have been inactive for too long"""
        while True:
            time.sleep(60)  # Check every minute
            current_time = time.time()
            inactive_users = []
            
            with self.users_lock:
                for username, (conn, addr, port, last_activity) in self.active_users.items():
                    # If inactive for more than 30 minutes, mark for removal
                    idle_time = current_time - last_activity
                    if idle_time > 1800:
                        inactive_users.append(username)
                        logger.debug(f"SESSION: User {username} inactive for {idle_time:.1f}s, marking for timeout")
                
                # Remove inactive users
                for username in inactive_users:
                    try:
                        conn, _, _, _ = self.active_users[username]
                        conn.close()
                    except:
                        pass
                    logger.info(f"SESSION: User {username} timed out and was logged out")
                    del self.active_users[username]
    
    def _cleanup_server_state(self) -> None:
        """Clean up expired puzzles, tokens and other temporary state"""
        while True:
            time.sleep(30)  # Run every 30 seconds
            current_time = time.time()
            
            # Clean up expired puzzles
            with self.puzzle_lock:
                expired_puzzles = []
                for username, puzzle in self.puzzles.items():
                    age = current_time - puzzle["timestamp"]
                    if age > 60:  # 1 minute expiry
                        expired_puzzles.append(username)
                        logger.debug(f"DOS-PROTECTION: Expiring puzzle for {username} (age: {age:.1f}s)")
                
                for username in expired_puzzles:
                    del self.puzzles[username]
                
                if expired_puzzles:
                    logger.info(f"DOS-PROTECTION: Expired {len(expired_puzzles)} puzzles")
                
            # Clean up auth attempts that are too old
            with self.auth_lock:
                expired_ips = []
                for ip in list(self.auth_attempts.keys()):
                    _, last_time = self.auth_attempts[ip]
                    age = current_time - last_time
                    if age > 3600:  # 1 hour
                        expired_ips.append(ip)
                
                for ip in expired_ips:
                    del self.auth_attempts[ip]
                    
                if expired_ips:
                    logger.info(f"DOS-PROTECTION: Reset auth attempts for {len(expired_ips)} IPs")
                
            # Clean up connection tracking for IPs
            with self.connection_tracker_lock:
                old_count = len(self.connection_tracker)
                self.connection_tracker = {k: v for k, v in self.connection_tracker.items() 
                                         if current_time - v["timestamp"] <= 60}
                
                if old_count > len(self.connection_tracker):
                    logger.debug(f"DOS-PROTECTION: Removed {old_count - len(self.connection_tracker)} expired connection trackers")
                
            # Clean up expired ephemeral keys
            with self.keys_lock:
                expired_keys = []
                for username, data in self.ephemeral_keys.items():
                    if "expiry" in data and data["expiry"] < current_time:
                        expired_keys.append(username)
                        logger.debug(f"SECURITY: Expiring ephemeral key for {username}")
                
                for username in expired_keys:
                    del self.ephemeral_keys[username]
                    
                if expired_keys:
                    logger.info(f"SECURITY: Expired ephemeral keys for {len(expired_keys)} users")
                    
                    # Save updated ephemeral keys
                    try:
                        with open(self.ephemeral_keys_file, 'w') as f:
                            encrypted_data = self._encrypt_data(self.ephemeral_keys)
                            f.write(encrypted_data)
                    except Exception as e:
                        logger.error(f"Error saving ephemeral keys: {e}")
    
    def _check_dos_protection(self, addr) -> bool:
        """Check if connection is allowed based on DoS protection"""
        with self.conn_lock:
            ip = addr[0]
            count = self.active_connections.get(ip, 0)
            
            if count >= self.max_conn_per_ip:
                logger.warning(f"DOS-PROTECTION: Rejected connection from {ip} (limit {self.max_conn_per_ip} exceeded)")
                return False
            
            self.active_connections[ip] = count + 1
            logger.debug(f"DOS-PROTECTION: Connection from {ip} allowed (count: {count+1}/{self.max_conn_per_ip})")
            return True
    
    def _release_connection(self, addr) -> None:
        """Release connection count for DoS protection"""
        with self.conn_lock:
            ip = addr[0]
            count = self.active_connections.get(ip, 0)
            
            if count > 0:
                self.active_connections[ip] = count - 1
                logger.debug(f"DOS-PROTECTION: Released connection from {ip} (count: {count-1}/{self.max_conn_per_ip})")
            elif ip in self.active_connections:
                del self.active_connections[ip]
                logger.debug(f"DOS-PROTECTION: Removed connection tracker for {ip}")
    
    def _generate_client_puzzle(self, username, ip_address, difficulty=3):
        """Generate a computational puzzle for DoS protection"""
        # Create a random challenge
        challenge = secrets.token_bytes(16)
        challenge_b64 = base64.b64encode(challenge).decode('utf-8')
        
        # Store the puzzle in server state
        with self.puzzle_lock:
            self.puzzles[username] = {
                "challenge": challenge,
                "difficulty": difficulty,
                "timestamp": time.time(),
                "ip_address": ip_address,
                "solved": False
            }
        
        logger.info(f"DOS-PROTECTION: Generated puzzle for {username} (difficulty: {difficulty}, IP: {ip_address})")
        
        # Return the challenge and target hash pattern
        return {
            "challenge": challenge_b64,
            "difficulty": difficulty
        }

    def _verify_puzzle_solution(self, username, solution):
        """Verify client's solution to the puzzle"""
        with self.puzzle_lock:
            if username not in self.puzzles:
                logger.warning(f"DOS-PROTECTION: No active puzzle found for {username}")
                return False
                
            puzzle = self.puzzles[username]
            if puzzle["solved"]:
                logger.warning(f"DOS-PROTECTION: Puzzle for {username} already solved (replay attempt?)")
                return False
                
            challenge = puzzle["challenge"]
            difficulty = puzzle["difficulty"]
            
            # Check if puzzle is expired (30 seconds)
            puzzle_age = time.time() - puzzle["timestamp"]
            if puzzle_age > 30:
                logger.info(f"DOS-PROTECTION: Puzzle for {username} expired (age: {puzzle_age:.1f}s)")
                del self.puzzles[username]
                return False
        
        try:
            solution_bytes = base64.b64decode(solution)
            
            # Check if hash of challenge + solution has required leading zeros
            hash_result = hashlib.sha256(challenge + solution_bytes).hexdigest()
            valid = hash_result.startswith("0" * difficulty)
            
            if valid:
                logger.info(f"DOS-PROTECTION: {username} solved puzzle correctly (hash: {hash_result[:difficulty+8]})")
                # Mark puzzle as solved
                with self.puzzle_lock:
                    if username in self.puzzles:
                        self.puzzles[username]["solved"] = True
            else:
                logger.warning(f"DOS-PROTECTION: {username} submitted invalid solution (hash: {hash_result[:difficulty+8]})")
            
            return valid
            
        except Exception as e:
            logger.error(f"Error verifying puzzle solution: {e}")
            return False
    
    def _enforce_consistent_timing(self, username, start_time):
        """Ensure consistent processing time to prevent timing attacks"""
        elapsed = time.time() - start_time
        avg_time = 0.1  # Default 100ms
        if elapsed < avg_time:
            sleep_time = avg_time - elapsed
            logger.debug(f"SECURITY: Adding {sleep_time:.3f}s delay for timing consistency (username: {username})")
            time.sleep(sleep_time)
    
    def start(self) -> None:
        """Start the server and handle incoming connections"""
        try:
            logger.info("Server is running. Press Ctrl+C to stop.")
            logger.info(f"Default users: {', '.join(self.default_users.keys())}")
            
            while True:
                conn, addr = self.server_socket.accept()
                logger.debug(f"NETWORK: Accepted connection from {addr[0]}:{addr[1]}")
                
                # Track connection rate
                with self.connection_tracker_lock:
                    ip = addr[0]
                    current_time = time.time()
                    
                    # Clean old entries (older than 60 seconds)
                    old_count = len(self.connection_tracker)
                    self.connection_tracker = {k: v for k, v in self.connection_tracker.items() 
                                            if current_time - v["timestamp"] <= 60}
                    
                    if old_count > len(self.connection_tracker):
                        logger.debug(f"DOS-PROTECTION: Cleaned up {old_count - len(self.connection_tracker)} expired connection trackers")
                                            
                    # Check rate limits
                    if ip in self.connection_tracker:
                        tracker = self.connection_tracker[ip]
                        
                        if tracker["count"] >= 30:  # Max 30 connections per minute
                            logger.warning(f"DOS-PROTECTION: Connection rate limit exceeded for {ip} ({tracker['count']} connections/min)")
                            try:
                                conn.send(json.dumps({
                                    "type": "ERROR",
                                    "message": "Connection rate limit exceeded. Please try again later."
                                }).encode('utf-8'))
                            except:
                                pass
                            conn.close()
                            continue
                            
                        # Update counter
                        tracker["count"] += 1
                        logger.debug(f"DOS-PROTECTION: Connection from {ip} allowed (rate: {tracker['count']}/min)")
                    else:
                        # New IP
                        self.connection_tracker[ip] = {
                            "count": 1,
                            "timestamp": current_time
                        }
                        logger.debug(f"DOS-PROTECTION: First connection from {ip} in this minute")
                
                # Check DoS protection (concurrent connections)
                if not self._check_dos_protection(addr):
                    conn.send(json.dumps({
                        "type": "ERROR",
                        "message": "Too many concurrent connections from your IP address"
                    }).encode('utf-8'))
                    conn.close()
                    continue
                
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
                logger.debug(f"NETWORK: Started handler thread for {addr[0]}:{addr[1]}")
                
        except KeyboardInterrupt:
            logger.info("Server shutting down.")
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            self.server_socket.close()
    
    def handle_client(self, conn, addr) -> None:
        """Handle a client connection"""
        username = None
        try:
            # Set socket timeout to prevent hanging connections
            conn.settimeout(300)  # 5 minutes timeout
            logger.debug(f"NETWORK: Set 5 minute timeout for connection from {addr[0]}:{addr[1]}")
            
            while True:
                data = conn.recv(4096)  # Increased buffer size for larger messages
                if not data:
                    logger.debug(f"NETWORK: Client disconnected (no data)")
                    break  # Client disconnected
                
                # Limit message size
                if len(data) > 1024 * 1024:  # 1MB limit
                    logger.warning(f"SECURITY: Message size limit exceeded from {addr} ({len(data)} bytes)")
                    conn.send(json.dumps({
                        "type": "ERROR",
                        "message": "Message too large"
                    }).encode('utf-8'))
                    break
                
                # Basic message validation
                try:
                    message = json.loads(data.decode('utf-8'))
                    
                    # Validate message has a type field
                    if 'type' not in message:
                        raise ValueError("Message missing 'type' field")
                        
                    # Type-specific validation
                    msg_type = message.get('type')
                    if msg_type == 'SRP-START' and ('username' not in message or 'A' not in message):
                        raise ValueError("Invalid SRP-START message format")
                    
                    if msg_type == 'SRP-VERIFY' and ('username' not in message or 'M' not in message):
                        raise ValueError("Invalid SRP-VERIFY message format")
                    
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"SECURITY: Invalid message format from {addr}: {e}")
                    conn.send(json.dumps({
                        "type": "ERROR",
                        "message": "Invalid message format"
                    }).encode('utf-8'))
                    continue
                
                logger.debug(f'NETWORK: Received {msg_type} message from {addr}')
                
                # Handle rate limiting for authentication
                if msg_type == 'SIGN-IN' or msg_type == 'SRP-START':
                    with self.auth_lock:
                        ip = addr[0]
                        current_time = time.time()
                        
                        if ip in self.auth_attempts:
                            attempts, last_time = self.auth_attempts[ip]
                            
                            # Reset attempts if more than 10 minutes have passed
                            if current_time - last_time > 600:
                                attempts = 0
                                logger.debug(f"DOS-PROTECTION: Reset auth attempts for {ip} (10min passed)")
                            
                            # Rate limit if too many attempts
                            if attempts >= 5 and current_time - last_time < 300:
                                logger.warning(f"DOS-PROTECTION: Too many login attempts from {ip} ({attempts} in last 5min)")
                                response = {
                                    "type": "LOGIN_FAIL",
                                    "message": "Too many login attempts. Please try again later."
                                }
                                conn.send(json.dumps(response).encode('utf-8'))
                                continue
                            
                            self.auth_attempts[ip] = (attempts + 1, current_time)
                            logger.debug(f"DOS-PROTECTION: Auth attempt from {ip} ({attempts+1} in window)")
                        else:
                            self.auth_attempts[ip] = (1, current_time)
                            logger.debug(f"DOS-PROTECTION: First auth attempt from {ip}")
                
                # Process message based on type
                if msg_type == 'SIGN-IN':
                    username = message.get('username')
                    response = self.handle_signin(message, conn, addr)
                elif msg_type == 'SRP-REGISTER':
                    username = message.get('username')
                    response = self.handle_srp_register(message)
                elif msg_type == 'SRP-START':
                    username = message.get('username')
                    response = self.handle_srp_start(message, addr)
                elif msg_type == 'SRP-VERIFY':
                    username = message.get('username')
                    response = self.handle_srp_verify(message, conn, addr)
                elif msg_type == 'SIGN-OUT':
                    response = self.handle_signout(message)
                    username = None
                elif msg_type == 'LIST':
                    response = self.handle_list(message)
                elif msg_type == 'ADDRESS_REQUEST':
                    response = self.handle_address_request(message)
                elif msg_type == 'KEY_STORE':
                    response = self.handle_key_store(message)
                elif msg_type == 'KEY_REQUEST':
                    response = self.handle_key_request(message)
                elif msg_type == 'UPDATE_PORT':
                    response = self.handle_port_update(message)
                else:
                    logger.warning(f"SECURITY: Unknown message type from {addr}: {msg_type}")
                    response = {
                        "type": "ERROR",
                        "message": f"Unknown message type: {msg_type}"
                    }
                
                if response is not None:
                    conn.send(json.dumps(response).encode('utf-8'))
                    logger.debug(f'NETWORK: Sent {response.get("type", "UNKNOWN")} response to {addr}')
                
                # Update last activity time for authenticated users
                if username in self.active_users:
                    _, _, port, _ = self.active_users[username]
                    self.active_users[username] = (conn, addr, port, time.time())
                    logger.debug(f"SESSION: Updated last activity time for {username}")

        except socket.timeout:
            logger.warning(f"NETWORK: Connection from {addr} timed out (5min inactivity)")
        except json.JSONDecodeError:
            logger.warning(f'SECURITY: Invalid JSON format from {addr}')
        except Exception as e:
            logger.error(f'Error handling client: {e}')
        finally:
            # Clean up connection
            if username:
                with self.users_lock:
                    if username in self.active_users:
                        del self.active_users[username]
                        logger.info(f"SESSION: User {username} disconnected")
                        
                    # Clean up any SRP sessions
                    if username in self.srp_sessions:
                        del self.srp_sessions[username]
                        logger.debug(f"SECURITY: Cleaned up SRP session for {username}")
            
            # Release connection for DoS protection
            self._release_connection(addr)
            
            conn.close()
            logger.info(f'NETWORK: Connection closed from {addr}')
    
    def handle_port_update(self, data) -> Dict[str, Any]:
        """Handle port update request from a client"""
        username = data.get('username')
        new_port = data.get('new_port')
        
        # Make sure the user is authenticated
        if username not in self.active_users:
            logger.warning(f"SECURITY: Unauthenticated port update request for {username}")
            return {
                "type": "PORT_UPDATE_RESPONSE",
                "success": False,
                "message": "Not authenticated"
            }
            
        # Update the user's port
        with self.users_lock:
            conn, addr, _, last_activity = self.active_users[username]
            self.active_users[username] = (conn, addr, new_port, last_activity)
            
        logger.info(f"ENDPOINT-HIDING: Updated listening port for {username} to {new_port}")
        
        return {
            "type": "PORT_UPDATE_RESPONSE",
            "success": True,
            "message": "Port updated successfully"
        }
    
    def handle_signin(self, data, conn, addr) -> Dict[str, Any]:
        """Handle legacy user sign-in (not SRP) - with constant time operations"""
        # This is kept for backward compatibility
        # SRP should be used for actual secure authentication
        username = data.get('username')
        password = data.get('password')
        receiver_port = data.get('reciever_port')
        
        # Record start time for constant-time processing
        start_time = time.time()
        logger.debug(f"SECURITY: Processing sign-in request for {username} (timing protected)")
        
        with self.users_lock:
            # Check if user exists
            if username not in self.credentials:
                # Ensure constant time processing
                self._enforce_consistent_timing(username, start_time)
                
                return {
                    "type": "LOGIN_FAIL",
                    "message": "Invalid username or password"
                }
            
            # Check if user is already logged in
            if username in self.active_users:
                # Ensure constant time processing
                self._enforce_consistent_timing(username, start_time)
                
                return {
                    "type": "LOGIN_FAIL",
                    "message": "User already logged in"
                }
            
            # Verify if this user uses SRP
            if "salt" in self.credentials[username] and "verifier" in self.credentials[username]:
                # Ensure constant time processing
                self._enforce_consistent_timing(username, start_time)
                
                return {
                    "type": "LOGIN_FAIL",
                    "message": "Please use secure authentication method",
                    "require_srp": True
                }
                
            # Legacy password verification (fallback for non-SRP users)
            stored_hash = self.credentials[username].get("password_hash")
            salt = self.credentials[username].get("salt")
            
            try:
                if stored_hash and salt:
                    # Legacy password verification
                    password_hash = hashlib.scrypt(
                        password.encode(),
                        salt=base64.b64decode(salt),
                        n=16384,
                        r=8,
                        p=1,
                        dklen=32
                    ).hex()
                    
                    if password_hash != stored_hash:
                        # Ensure constant time processing
                        self._enforce_consistent_timing(username, start_time)
                        
                        return {
                            "type": "LOGIN_FAIL",
                            "message": "Invalid username or password"
                        }
                    
                    # Add user to active users
                    self.active_users[username] = (conn, addr, receiver_port, time.time())
                    
                    # Reset authentication attempts on successful login
                    with self.auth_lock:
                        ip = addr[0]
                        if ip in self.auth_attempts:
                            self.auth_attempts[ip] = (0, time.time())
                    
                    # Reset failed attempts counter in credentials
                    if "failed_attempts" in self.credentials[username]:
                        self.credentials[username]["failed_attempts"] = 0
                        self.credentials[username]["last_failed_login"] = 0
                        self._save_credentials()
                    
                    logger.info(f'SESSION: User {username} signed in from {addr[0]}:{addr[1]}, listening on port {receiver_port}')
                    
                    # Ensure constant time processing
                    self._enforce_consistent_timing(username, start_time)
                    return {
                        "type": "LOGIN_SUCCESS",
                        "message": f"Welcome, {username}!"
                    }
                else:
                    # Ensure constant time processing
                    self._enforce_consistent_timing(username, start_time)
                    
                    return {
                        "type": "LOGIN_FAIL",
                        "message": "Invalid username or password"
                    }
            except Exception as e:
                logger.error(f"Error in password verification: {e}")
                
                # Ensure constant time processing
                self._enforce_consistent_timing(username, start_time)
                
                return {
                    "type": "LOGIN_FAIL",
                    "message": "Authentication error"
                }
    
    def handle_srp_register(self, data) -> Dict[str, Any]:
        """Handle SRP registration with enhanced security"""
        username = data.get('username')
        salt_b64 = data.get('salt')
        verifier_hex = data.get('verifier')
        
        # Add password strength check (based on verifier entropy)
        try:
            verifier = int(verifier_hex, 16)
            # Check for password strength based on verifier bit length
            bit_length = verifier.bit_length()
            logger.debug(f"SECURITY: Registration for {username} with verifier bit length: {bit_length}")
            
            if bit_length < 512:
                logger.warning(f"SECURITY: Rejected weak password for {username} (verifier bit length: {bit_length})")
                return {
                    "type": "REGISTER_RESPONSE",
                    "success": False,
                    "message": "Password appears to be too weak"
                }
        except ValueError:
            logger.warning(f"SECURITY: Invalid verifier format in registration for {username}")
            return {
                "type": "REGISTER_RESPONSE",
                "success": False,
                "message": "Invalid verifier format"
            }
        
        # Basic username validation
        if not username or len(username) < 3 or len(username) > 32:
            logger.warning(f"SECURITY: Invalid username length ({len(username) if username else 0})")
            return {
                "type": "REGISTER_RESPONSE",
                "success": False,
                "message": "Username must be between 3 and 32 characters"
            }
            
        # Check for invalid characters in username
        if not all(c.isalnum() or c == '_' or c == '-' for c in username):
            logger.warning(f"SECURITY: Username contains invalid characters: {username}")
            return {
                "type": "REGISTER_RESPONSE",
                "success": False,
                "message": "Username can only contain letters, numbers, underscores, and hyphens"
            }
        
        # Verify the username isn't already taken
        with self.users_lock:
            if username in self.credentials:
                logger.warning(f"SECURITY: Registration attempt for existing username: {username}")
                return {
                    "type": "REGISTER_RESPONSE",
                    "success": False,
                    "message": "Username already exists"
                }
        
        # Username policy check - prevent registration flooding
        username_count = 0
        recent_registrations = []
        for existing_user, data in self.credentials.items():
            if "registration_time" in data and time.time() - data["registration_time"] < 3600:
                username_count += 1
                recent_registrations.append(existing_user)
        
        if username_count > 10:  # More than 10 registrations in the last hour
            logger.warning(f"DOS-PROTECTION: Registration limit exceeded (recent users: {recent_registrations})")
            return {
                "type": "REGISTER_RESPONSE",
                "success": False,
                "message": "Too many registrations. Please try again later."
            }
        
        try:
            # Store user credentials with SRP data
            with self.users_lock:
                # Add a random identifier for the user to prevent enumeration attacks
                user_id = secrets.token_hex(16)
                
                self.credentials[username] = {
                    "salt": salt_b64,
                    "verifier": verifier_hex,
                    "registration_time": int(time.time()),
                    "user_id": user_id,
                    "failed_attempts": 0,
                    "last_failed_login": 0
                }
                self._save_credentials()
            
            logger.info(f"SECURITY: User {username} registered successfully using SRP (verifier bit length: {bit_length})")
            
            return {
                "type": "REGISTER_RESPONSE",
                "success": True,
                "message": f"User {username} registered successfully"
            }
            
        except Exception as e:
            logger.error(f"Error in SRP registration: {e}")
            return {
                "type": "REGISTER_RESPONSE",
                "success": False,
                "message": f"Registration error: {str(e)}"
            }
    
    def handle_srp_start(self, data, addr) -> Dict[str, Any]:
        """Handle the start of SRP authentication with enhanced security"""
        username = data.get('username')
        A_hex = data.get('A')
        
        logger.debug(f"SECURITY: Processing SRP-START for {username}")
        
        # Add puzzle solution verification
        puzzle_solution = data.get('puzzle_solution')
        
        # Check if user has an active puzzle that needs to be solved
        with self.puzzle_lock:
            if username in self.puzzles and not self.puzzles[username]["solved"]:
                puzzle_age = time.time() - self.puzzles[username]["timestamp"]
                if not puzzle_solution:
                    # User has a puzzle but didn't provide a solution, send a puzzle challenge
                    logger.info(f"DOS-PROTECTION: {username} needs to solve puzzle (age: {puzzle_age:.1f}s)")
                    puzzle = self._generate_client_puzzle(username, addr[0], difficulty=3)
                    return {
                        "type": "PUZZLE_CHALLENGE",
                        "puzzle": puzzle["challenge"],
                        "difficulty": puzzle["difficulty"]
                    }
                
                # User provided a solution, verify it
                logger.debug(f"DOS-PROTECTION: Verifying puzzle solution for {username}")
                if not self._verify_puzzle_solution(username, puzzle_solution):
                    # Solution not correct, send a new puzzle
                    logger.warning(f"DOS-PROTECTION: Invalid puzzle solution from {username}")
                    puzzle = self._generate_client_puzzle(username, addr[0], difficulty=3)
                    return {
                        "type": "PUZZLE_CHALLENGE",
                        "puzzle": puzzle["challenge"],
                        "difficulty": puzzle["difficulty"],
                        "message": "Invalid puzzle solution"
                    }
                
                logger.info(f"DOS-PROTECTION: {username} solved puzzle correctly")
        
        # Add constant time username check to prevent timing attacks
        # Get current time to ensure consistent timing for this username
        start_time = time.time()
        
        # Record this attempt time in our tracking dictionary
        with self.username_attempt_lock:
            self.last_username_attempt[username] = start_time
        
        # Check if user exists
        user_exists = username in self.credentials
        
        # Additional verification - check failed attempts and possibly trigger a puzzle
        if user_exists:
            user_data = self.credentials[username]
            # Check if user has too many failed attempts
            failed_attempts = user_data.get("failed_attempts", 0)
            if failed_attempts >= 3:
                last_failed = user_data.get("last_failed_login", 0)
                current_time = time.time()
                time_since_failure = current_time - last_failed
                
                # If last failure was within the last 10 minutes
                if time_since_failure < 600:
                    # Generate a puzzle if user doesn't already have one
                    with self.puzzle_lock:
                        if username not in self.puzzles:
                            # Difficulty increases with more failures
                            difficulty = min(3 + (failed_attempts - 3), 5)
                            logger.warning(f"SECURITY: Account protection for {username} " +
                                          f"({failed_attempts} failed attempts, last: {time_since_failure:.1f}s ago)")
                            puzzle = self._generate_client_puzzle(username, addr[0], difficulty)
                            
                            # Ensure consistent timing
                            self._enforce_consistent_timing(username, start_time)
                            
                            return {
                                "type": "PUZZLE_CHALLENGE",
                                "puzzle": puzzle["challenge"],
                                "difficulty": puzzle["difficulty"],
                                "message": "Account has been temporarily locked due to too many failed attempts"
                            }
        
        # SRP processing happens here (as in your original code)
        with self.users_lock:
            if not user_exists:
                # Generate fake response to prevent username enumeration
                fake_salt = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
                fake_B = hex(random.randint(1, self.srp_server.N - 1))[2:]
                
                logger.debug(f"SECURITY: Generated fake SRP response for non-existent user {username}")
                
                # Wait a consistent amount of time to prevent timing attacks
                self._enforce_consistent_timing(username, start_time)
                
                return {
                    "type": "SRP-CHALLENGE",
                    "salt": fake_salt,
                    "B": fake_B
                }
            
            # Check if user is already logged in
            if username in self.active_users:
                # Wait a consistent amount of time to prevent timing attacks
                self._enforce_consistent_timing(username, start_time)
                
                logger.warning(f"SECURITY: Rejected login for already logged in user: {username}")
                return {
                    "type": "LOGIN_FAIL",
                    "message": "User already logged in"
                }
            
            # Get user's salt and verifier
            salt_b64 = self.credentials[username].get("salt")
            verifier_hex = self.credentials[username].get("verifier")
            
            if not salt_b64 or not verifier_hex:
                # Wait a consistent amount of time to prevent timing attacks
                self._enforce_consistent_timing(username, start_time)
                
                logger.warning(f"SECURITY: Missing credentials data for {username}")
                return {
                    "type": "LOGIN_FAIL",
                    "message": "User credentials not found"
                }
            
            try:
                # Decode salt and convert verifier to int
                salt = base64.b64decode(salt_b64)
                v = int(verifier_hex, 16)
                
                # Convert client's public value (A) from hex to int
                A = int(A_hex, 16)
                
                # Verify A is not 0 (security check)
                if A % self.srp_server.N == 0:
                    # Wait a consistent amount of time to prevent timing attacks
                    self._enforce_consistent_timing(username, start_time)
                    
                    logger.warning(f"SECURITY: Zero modulo attack attempt on SRP for {username}")
                    return {
                        "type": "LOGIN_FAIL",
                        "message": "Invalid authentication parameters"
                    }
                
                # Generate server's credentials
                b, B = self.srp_server.generate_server_credentials(username, v)
                
                # Store SRP session data
                self.srp_sessions[username] = {
                    "salt": salt,
                    "A": A,
                    "B": B,
                    "b": b,
                    "v": v,
                    "timestamp": time.time()
                }
                
                logger.debug(f"SECURITY: SRP challenge prepared for {username} (client A bit length: {A.bit_length()}, server B bit length: {B.bit_length()})")
                
                # Wait a consistent amount of time to prevent timing attacks
                self._enforce_consistent_timing(username, start_time)
                
                # Send challenge
                return {
                    "type": "SRP-CHALLENGE",
                    "salt": salt_b64,
                    "B": hex(B)[2:]  # Convert to hex string without '0x' prefix
                }
                
            except Exception as e:
                logger.error(f"Error in SRP start: {e}")
                
                # Wait a consistent amount of time to prevent timing attacks
                self._enforce_consistent_timing(username, start_time)
                
                return {
                    "type": "LOGIN_FAIL",
                    "message": "Authentication error"
                }
    
    def handle_srp_verify(self, data, conn, addr) -> Dict[str, Any]:
        """Handle SRP verification with enhanced security"""
        username = data.get('username')
        M_hex = data.get('M')
        receiver_port = data.get('reciever_port')
        
        # Record start time for constant-time processing
        start_time = time.time()
        logger.debug(f"SECURITY: Processing SRP verification for {username}")
        
        # Verify the SRP session exists
        if username not in self.srp_sessions:
            # Ensure constant time processing
            self._enforce_consistent_timing(username, start_time)
            
            logger.warning(f"SECURITY: No active SRP session for {username}")
            return {
                "type": "LOGIN_FAIL",
                "message": "Authentication session expired"
            }
            
        # Get session data
        session = self.srp_sessions[username]
        A = session["A"]
        B = session["B"]
        salt = session["salt"]
        v = session["v"]
        b = session["b"]
        
        try:
            # Convert client proof from hex
            M = bytes.fromhex(M_hex)
            
            # Verify client proof and generate server proof
            result = self.srp_server.verify_client_proof(
                username, salt, A, B, M, v, b
            )
            
            if not result:
                logger.warning(f"SECURITY: SRP authentication failed for {username}: Invalid proof")
                
                # Update failed attempts counter
                with self.users_lock:
                    user_data = self.credentials.get(username, {})
                    failed_attempts = user_data.get("failed_attempts", 0) + 1
                    user_data["failed_attempts"] = failed_attempts
                    user_data["last_failed_login"] = int(time.time())
                    self.credentials[username] = user_data
                    self._save_credentials()
                    logger.info(f"SECURITY: Updated failed attempts for {username} to {failed_attempts}")
                
                # Ensure constant time processing
                self._enforce_consistent_timing(username, start_time)
                
                return {
                    "type": "LOGIN_FAIL",
                    "message": "Invalid username or password"
                }
                
            HAMK, session_key = result
            
            # Add user to active users
            self.active_users[username] = (conn, addr, receiver_port, time.time())
            
            # Clean up the SRP session
            del self.srp_sessions[username]
            
            # Reset authentication attempts on successful login
            with self.auth_lock:
                ip = addr[0]
                if ip in self.auth_attempts:
                    self.auth_attempts[ip] = (0, time.time())
                    logger.debug(f"SECURITY: Reset auth attempts for {ip} after successful login")
            
            # Reset failed attempts counter in credentials
            with self.users_lock:
                if username in self.credentials:
                    prev_failed = self.credentials[username].get("failed_attempts", 0)
                    self.credentials[username]["failed_attempts"] = 0
                    self.credentials[username]["last_failed_login"] = 0
                    self._save_credentials()
                    if prev_failed > 0:
                        logger.info(f"SECURITY: Reset failed attempts for {username} (was: {prev_failed})")
            
            # Get session key hash for logging
            session_key_hash = hashlib.sha256(session_key).hexdigest()[:8]
            logger.info(f'SESSION: User {username} authenticated via SRP from {addr[0]}:{addr[1]}, listening on port {receiver_port} (key hash: {session_key_hash})')
            
            # Ensure constant time processing
            self._enforce_consistent_timing(username, start_time)
            
            return {
                "type": "LOGIN_SUCCESS",
                "message": f"Welcome, {username}!",
                "HAMK": HAMK.hex(),
                "session_key": session_key.hex()
            }
            
        except Exception as e:
            logger.error(f"Error in SRP verification: {e}")
            
            # Clean up the SRP session
            if username in self.srp_sessions:
                del self.srp_sessions[username]
            
            # Ensure constant time processing
            self._enforce_consistent_timing(username, start_time)
            
            return {
                "type": "LOGIN_FAIL",
                "message": f"Authentication error: {str(e)}"
            }
    
    def handle_signout(self, data) -> Dict[str, Any]:
        """Handle user sign-out"""
        username = data.get('username')
        
        with self.users_lock:
            if username in self.active_users:
                del self.active_users[username]
                logger.info(f'SESSION: User {username} signed out')
        
        return {
            "type": "RESPONSE",
            "message": f"You have been signed out, {username}."
        }
    
    def handle_list(self, data) -> Dict[str, Any]:
        """Handle request for list of active users"""
        username = data.get('username')
        
        with self.users_lock:
            user_list = list(self.active_users.keys())
        
        logger.info(f'SESSION: User {username} requested list of active users ({len(user_list)} online)')
        
        return {
            "type": "RESPONSE",
            "message": f"Active users: {', '.join(user_list)}"
        }
    
    def handle_address_request(self, data) -> Dict[str, Any]:
        """Handle request for a user's address with enhanced security"""
        source_user = data.get('source_user')
        requested_user = data.get('requested_user')
        
        # Validate source user is authenticated
        if source_user not in self.active_users:
            logger.warning(f"SECURITY: Unauthenticated address request from {source_user}")
            return {
                "type": "RESPONSE",
                "message": "Not authenticated"
            }
        
        with self.users_lock:
            if requested_user not in self.active_users:
                logger.warning(f"ENDPOINT-HIDING: {source_user} requested address of offline user {requested_user}")
                return {
                    "type": "RESPONSE",
                    "message": f"User {requested_user} is not online."
                }
            
            conn, addr, port, _ = self.active_users[requested_user]
            
            logger.info(f'ENDPOINT-HIDING: User {source_user} requested address of {requested_user} ({addr[0]}:{port})')
            
            # Add ephemeral authorization token for this address request
            token = secrets.token_hex(16)
            timestamp = int(time.time())
            
            logger.debug(f"ENDPOINT-HIDING: Generated auth token for {source_user} → {requested_user} ({token[:8]}...)")
            
            return {
                "type": "ADDRESS",
                "requested_user_username": requested_user,
                "requested_user_ip": addr[0],
                "requested_user_listener_port": port,
                "authorization_token": token,
                "timestamp": timestamp
            }
    
    def handle_key_store(self, data) -> Dict[str, Any]:
        """Handle storing a user's ephemeral public key with enhanced security"""
        username = data.get('username')
        public_key = data.get('public_key')
        expiry = data.get('expiry', int(time.time()) + 86400)  # Default expiry is 24 hours
        
        # Validate username is authenticated
        if username not in self.active_users:
            logger.warning(f"SECURITY: Unauthenticated key store attempt for {username}")
            return {
                "type": "KEY_STORE_RESPONSE",
                "success": False,
                "message": "Not authenticated"
            }
        
        # Basic validation of public key format
        try:
            # Attempt to load the key to verify format
            key_obj = serialization.load_pem_public_key(
                public_key.encode('utf-8'),
                backend=default_backend()
            )
            
            # Verify it's an EC key
            if not isinstance(key_obj, ec.EllipticCurvePublicKey):
                logger.warning(f"SECURITY: Invalid key type from {username} (not EC)")
                return {
                    "type": "KEY_STORE_RESPONSE",
                    "success": False,
                    "message": "Invalid key format - must be EC key"
                }
                
            # Calculate key fingerprint for logging
            der_data = key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            fingerprint = hashlib.sha256(der_data).hexdigest()[:8]
            
        except Exception as e:
            logger.error(f"SECURITY: Invalid public key format from {username}: {e}")
            return {
                "type": "KEY_STORE_RESPONSE",
                "success": False,
                "message": "Invalid public key format"
            }
        
        with self.keys_lock:
            self.ephemeral_keys[username] = {
                "public_key": public_key,
                "timestamp": int(time.time()),
                "expiry": expiry
            }
            
            # Save to encrypted file
            with open(self.ephemeral_keys_file, 'w') as f:
                encrypted_data = self._encrypt_data(self.ephemeral_keys)
                f.write(encrypted_data)
        
        logger.info(f'SECURITY: Stored ephemeral public key for {username} (fingerprint: {fingerprint}, expiry: {expiry})')
        
        return {
            "type": "KEY_STORE_RESPONSE",
            "success": True,
            "message": "Key stored successfully"
        }
    
    def handle_key_request(self, data) -> Dict[str, Any]:
        """Handle request for a user's ephemeral public key"""
        requester = data.get('requester')
        requested_user = data.get('requested_user')
        
        # Validate requester is authenticated
        if requester not in self.active_users:
            logger.warning(f"SECURITY: Unauthenticated key request from {requester}")
            return {
                "type": "KEY_REQUEST_RESPONSE",
                "success": False,
                "message": "Not authenticated"
            }
        
        with self.keys_lock:
            if requested_user not in self.ephemeral_keys:
                logger.warning(f"SECURITY: Key requested for {requested_user} by {requester}, but no key found")
                return {
                    "type": "KEY_REQUEST_RESPONSE",
                    "success": False,
                    "message": f"No key found for {requested_user}"
                }
            
            key_data = self.ephemeral_keys[requested_user]
            current_time = int(time.time())
            
            # Check if key has expired
            if key_data["expiry"] < current_time:
                time_expired = current_time - key_data["expiry"]
                logger.warning(f"SECURITY: Requested key for {requested_user} has expired ({time_expired}s ago)")
                return {
                    "type": "KEY_REQUEST_RESPONSE",
                    "success": False,
                    "message": f"Key for {requested_user} has expired"
                }
            
            # Get key fingerprint for logging
            try:
                key_obj = serialization.load_pem_public_key(key_data["public_key"].encode('utf-8'), backend=default_backend())
                der_data = key_obj.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                fingerprint = hashlib.sha256(der_data).hexdigest()[:8]
            except:
                fingerprint = "unknown"
        
        logger.info(f'SECURITY: User {requester} requested ephemeral key of {requested_user} (fingerprint: {fingerprint})')
        
        return {
            "type": "KEY_REQUEST_RESPONSE",
            "success": True,
            "user": requested_user,
            "public_key": key_data["public_key"],
            "timestamp": key_data["timestamp"],
            "expiry": key_data["expiry"]
        }
        
    def create_hmac(self, key, data):
        """Create an HMAC for data integrity verification"""
        # Use the standard library hmac module
        h = hmac.new(key, digestmod=hashlib.sha256)
        h.update(data)
        hmac_value = h.digest()
        
        # Get hash prefix for logging
        hmac_hash = h.hexdigest()[:8]
        logger.debug(f"SECURITY: Generated HMAC (hash prefix: {hmac_hash})")
        
        return hmac_value

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Secure Messenger Server")
    parser.add_argument('-sp', '--port', type=int, help='Port number to listen on', default=50005)
    parser.add_argument('-sip', '--ip', type=str, help='IP address to listen on', default='127.0.0.1')
    parser.add_argument('-d', '--data-dir', type=str, help='Directory to store data', default='./data')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    server = Server(args.port, args.ip, args.data_dir)
    server.start()
import socket
import json
import argparse
import threading

##TODO -  When someone logs out we should broadcast to all clients that they have logged out.
class Server:
    def __init__(self, port, ip):
        self.ip = ip
        self.port = port

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5) # Can handle 5 clients at a time
        print(f'[*] Server started on {self.ip}:{self.port}')
        
        self.knownClients = {} # Map of {username: (connection, address, receiver_port)}
        self.clients_lock = threading.Lock()

    def start(self):
        try:
            while True:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
        except KeyboardInterrupt:
            print("Server shutting down.")
        except Exception as e:
            print("Error:", e)
        finally:
            self.server_socket.close()
    

    def handle_client(self, conn, addr):
        username = None
        try:
            while True:
                data = conn.recv(1024) # Recieving in chunks of 1024 bytes
                if not data:
                    break # Client disconnected since there is no data
                message = json.loads(data.decode('utf-8'))
                msg_type = message.get('type')
                if msg_type == 'SIGN-IN':
                    username = message.get('username')
                    rsp = self.handleSIGNIN(message, conn, addr)
                elif msg_type == 'SIGN-OUT':
                    rsp = self.handleSIGNOUT(message)
                elif msg_type == 'LIST':
                    rsp = self.handleLIST(message)
                elif msg_type == 'ADDRESS_REQUEST':
                    rsp = self.handleADDRESS_REQUEST(message)
                if rsp is not None:
                    conn.send(json.dumps(rsp).encode('utf-8'))

        except json.JSONDecodeError:
            print(f'[*] Invalid JSON format from {addr}')
        except Exception as e:
            print(f'[*] Error: {e}')
        finally:
            if username:
                with self.clients_lock:
                    if username in self.knownClients:
                        del self.knownClients[username]
            conn.close()
            print(f'[*] Connection closed from {addr}')
                

    def handleSIGNIN(self, data, conn, address):
        '''
            When a client signs in, save their username and address in the users dictionary.
            This will be useful when another clients request sthe destination of a user.
        '''
        with self.clients_lock:
            self.knownClients[data['username']] = (conn, address, data['reciever_port'])
        print(f'[*] User Signed In: {data["username"]} at {address} recieves messages on port {data["reciever_port"]}')
        packet = {
            "type": "RESPONSE",
            "message": f'{data["username"]} Successfully Signed In'
        }
        return packet
    
    def handleSIGNOUT(self, data):
        '''
            Removes a client from the user dictionary to ensure consistency of the list command.
        '''
        del self.knownClients[data['username']]
        print(f'[*] User Signed Out: {data["username"]}')
        packet = {
            "type": "RESPONSE",
            "message": f'{data["username"]} Successfully Signed Out'
        }
        return packet

    def handleLIST(self, data):
        '''
            When a client requests a list of signed in users, return a list of all signed in users.
        '''
        print(f'[*] List Requested by {data["username"]}')
        with self.clients_lock:
            user_list = list(self.knownClients.keys())
        packet = {
            "type": "RESPONSE",
            "message": 'Signed In Users: ' + ', '.join(user_list)
        }
        return packet

    def handleADDRESS_REQUEST(self, data):
        '''
            When a client needs to send a message, they need to request the server for the location of that client.
            Return the address of the request user in the packet to be sent back to client.
        '''
        with self.clients_lock:
            requested_user = data['requested_user']
            if requested_user not in self.knownClients:
                print(f'[*] User {requested_user} not signed in.')
                packet = {
                    "type": "RESPONSE",
                    "message": f'User {requested_user} is not signed in.'
                }
                return packet
            else:
                print(f'[*] Address Rquested by {data["source_user"]} for {requested_user}')
                packet = {
                    "type": "ADDRESS",
                    "requested_user_username": data['requested_user'], 
                    "requested_user_ip": self.knownClients[requested_user][1][0], # IP address of the requested user I THINK DOUBLE CHECK
                    "requested_user_listener_port": self.knownClients[requested_user][2], # Listening port of the requested user
                }
                return packet

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', type=int, help='Port number to listen on') # Use Port 50005
    parser.add_argument('-sip', type=str, help='IP address to listen on', default='127.0.0.1') # Use IP
    server = Server(parser.parse_args().sp, parser.parse_args().sip)
    server.start()
    server.close()
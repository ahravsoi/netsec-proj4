import socket
import argparse
import json
import signal
import sys
import threading

class Client:
    def __init__(self, username, ip, port):
        '''
            Set up the client and bind it to the given port and ip, save ths server address
            as we will use it multiplee times.

            - Runs the login commad to register the client with the server.
            - Signal handler is set up to handle the logout command.
            - known_peers is a cache that will store the address of the peers that the client knows about, so
               subsequent messages can be sent directly to the peer without asking the server for the address.
        '''
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_address = (ip, port)
            #self.server_address = ('127.0.0.1', 9090)
        except Exception as e:
            print(f'Error while initializing client: {e}')

        self.username = username
        self.known_peers = {}
        self.running = True

        try:
            signal.signal(signal.SIGINT, self.logout)
            self.login_status = False
            self.login(username)
        except Exception as e:
            print(f'Error while logging in: {e}')

    def receiver(self):
        '''
            Listen for incoming messages and handle them based on the type of message.
            Seperate thread so that we can consistently listen for inbound messages from any destination,
            
            This was added as I realized the messages will not only becoming from the server but from destinations
            that may be unknown to us at the time.
        '''
        while self.running:
            try:
                data, address = self.client_socket.recvfrom(1024)
                message = json.loads(data.decode())
            except Exception as e:
                print(f'Error while receiving message: {e}')
            
            if message['type'] == 'RESPONSE':
                print(f'{message["message"]}')
            if message['type'] == 'MESSAGE':
                print(f'<From {message["source_ip"]}:{message["source_port"]}:{message["source_user"]}> {message["message"]}')
            if message['type'] == 'ADDRESS':
                self.known_peers[message['username']] = message['address']
            print("Please Enter Command:", end='\n', flush=True) # Gimmick that will reprint the command prompt after a message comes in

    def start(self):
        '''
            Start the reciever thread to we can listen for incoming messages.
            Starts the command line to listen for user input and handle the commands accordigly

            Supports LIST and SEND commands.

            Keyboard interrupt will trigger the logout function.
        '''
        receiver_thread = threading.Thread(target=self.receiver)
        receiver_thread.daemon = True
        receiver_thread.start()

        print('Commands: LIST, SEND')
        rsp = None
        try: 
            while True:
                command = input("Please Enter Command:\n")
                command_parts = command.split(maxsplit=2)
                if command_parts[0].lower() == "list":
                    rsp = self.handleLIST()
                elif len(command_parts) == 3 and command_parts[0].lower() == "send":
                    destination_username = command_parts[1]
                    message = command_parts[2]
                    rsp = self.handleSEND(destination_username, message)
                else:
                    print("Invalid Command")

                if rsp is not None:
                    print(rsp)
        except KeyboardInterrupt:
            print("Logging out")
            self.logout()
        except Exception as e:
            print(f'Error while listening for user commands: {e}')
            

    def close(self):
        self.client_socket.close()

    def logout(self, signum, frame):
        '''
            Used when a keyboard interrupt is detected, this will send a sign out message to the server
        '''
        packet = {
            "type": "SIGN-OUT",
            "username": self.username
        }
        self.sendRequest(packet, self.server_address)
        self.running = False
        self.close()
        sys.exit(0)
       
    
    def login(self, username):
        '''
            Send a sign in message to the server to register the client.
        '''
        packet = {
            "type": "SIGN-IN",
            "username": username
        }
        self.sendRequest(packet, self.server_address)
        

    def handleLIST(self):
        '''
            Send a list request to the server to get a list of all signed in users
        '''
        packet = {
            "type": "LIST",
            "username": self.username
        }
        self.sendRequest(packet, self.server_address)

    
    def handleSEND(self, dest_user, msg):
        '''
            Send a message to a destination user, if the destination user is not in the known_peers cache,
            request the server for the address of the destination
        '''
        packet = {
            "type": "MESSAGE",
            "source_user": self.username,
            "source_ip": self.address[0],
            "source_port": self.address[1],
            "to": dest_user,
            "message": msg
        }
        dest = tuple(self.get_destAddress(dest_user))
        self.sendRequest(packet, dest)
   
    
    def get_destAddress(self, dest_user):
        '''
            Get the address of the destination user, if the destination user is not in the known_peers cache,
        '''
        if dest_user in self.known_peers:
            return self.known_peers[dest_user]
        else:
            packet = {
                "type": "ADDRESS_REQUEST",
                "source_user": self.username,
                "requested_user": dest_user
            }
            self.sendRequest(packet, self.server_address)
            while dest_user not in self.known_peers: # Wait for the local peers table to get updated
                pass
            return self.known_peers[dest_user]

    def sendRequest(self, packet, address):
        '''
            Send a packet to a given address. 
        '''
        try:
            self.client_socket.sendto(json.dumps(packet).encode(), address)
        except Exception as e:
            print(f'Error while sending request: {e}')
            print(f'DEBUG: packet: {packet}, address: {address}')

        


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', type=str, help='Username')
    parser.add_argument('-sip', type=str, help='Server IP address', default='127.0.0.1')
    parser.add_argument('-sp', type=int, help='Server port number')
    args = parser.parse_args()
    client = Client(args.u, args.sip, args.sp)
    client.start()
    client.close()
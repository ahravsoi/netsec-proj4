import socket
import json
import argparse

class Server:
    def __init__(self, port, ip):
        ''' 
            Set up the server and bind it to the given port and ip 
            retrieved from the command line
        '''
        try: 
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.address = (str(ip), port)
            self.server_socket.bind(self.address)
            print('Server Initialized on port: ', port)
        except Exception as e:
            print(f'Error while initializing server: {e}')

        self.users = {}

    def start(self):
        '''
            Start the server and listen for incoming messages, handle each case of message
            using the 'TYPE' feild of inbound messages. Delegates to the appropriate handler.

            Sends response back to the client to confirm the action was successful.
        '''
        try:
            while True:
                data, address = self.server_socket.recvfrom(1024)
                data = json.loads(data.decode())
                if data['type'] == 'SIGN-IN':
                    rsp = self.handleSIGNIN(data, address)
                elif data['type'] == 'SIGN-OUT':
                    rsp = self.handleSIGNOUT(data)
                elif data['type'] == 'LIST':
                    rsp = self.handleLIST(data)
                elif data['type'] == 'ADDRESS_REQUEST':
                    rsp = self.handleADDRESS_REQUEST(data)
                if rsp is not None:
                    self.server_socket.sendto(json.dumps(rsp).encode(), address)
        except Exception as e:
            print(f'Error while listening for client requests: {e}' )


    def handleSIGNIN(self, data, address):
        '''
            When a client signs in, save their username and address in the users dictionary.
            This will be useful when another clients request sthe destination of a user.
        '''
        self.users[data['username']] = address
        print(f'[*] User Signed In: {data["username"]} at {address}')
        packet = {
            "type": "RESPONSE",
            "message": f'{data["username"]} Successfully Signed In'
        }
        return packet
    
    def handleSIGNOUT(self, data):
        '''
            Removes a client from the user dictionary to ensure consistency of the list command.
        '''
        del self.users[data['username']]
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
        packet = {
            "type": "RESPONSE",
            "message": 'Signed In Users: ' + ', '.join(self.users.keys())
        }
        return packet

    def handleADDRESS_REQUEST(self, data):
        '''
            When a client needs to send a message, they need to request the server for the location of that client.
            Return the address of the request user in the packet to be sent back to client.
        '''
        if data['requested_user'] not in self.users:
            print(f'[*] User {data["requested_user"]} not signed in.')
            packet = {
                "type": "RESPONSE",
                "message": f'User {data["requested_user"]} is not signed in.'
            }
            return packet
        print(f'[*] Address Rquested by {data["source_user"]} for {data["requested_user"]}')
        packet = {
            "type": "ADDRESS",
            "username": data['requested_user'],
            "address": self.users[data['requested_user']]
        }
        return packet
    
    def close(self):
        # Close the socket
        self.server_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', type=int, help='Port number to listen on') # Use Port 50005
    parser.add_argument('-sip', type=str, help='IP address to listen on', default='127.0.0.1') # Use IP
    server = Server(parser.parse_args().sp, parser.parse_args().sip)
    server.start()
    server.close()
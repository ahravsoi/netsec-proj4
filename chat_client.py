import socket
import argparse
import json
import signal
import sys
import threading

class Client:
    def __init__(self, username, ip, port):
        pass

    def handle_message(self, message):
        pass

    def start(self):
        pass

    def sendRequest(self, packet):
        pass

    def logout(self, signum=None, frame=None):
        packet = {
            "type": "SIGN-OUT",
            "username": self.username
        }
        self.sendRequest(packet)
        self.running = False
        self.close()
        sys.exit(0)

    def login(self, username):
        packet = {
            "type": "SIGN-IN",
            "username": username
        }
        self.sendRequest(packet)

    def handleLIST(self):
        packet = {
            "type": "LIST",
            "username": self.username
        }
        self.sendRequest(packet)

    def handleSEND(self, dest_user, msg):
        packet = {
            "type": "MESSAGE",
            "source_user": self.username,
            "to": dest_user,
            "message": msg
        }
        self.sendRequest(packet)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', type=str, help='Username')
    parser.add_argument('-sip', type=str, help='Server IP address', default='127.0.0.1')
    parser.add_argument('-sp', type=int, help='Server port number')
    args = parser.parse_args()
    client = Client(args.u, args.sip, args.sp)
    client.start()
    client.close()

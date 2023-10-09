import socket
import sys
import os
import time
import pickle
import threading
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import handshake

filedict = {}

def connect():
    global filedict
    client_socket = ""
    f = ""
    toprint = ["emptiness"]
    if os.path.isfile("config.json"):
        with open("config.json","r") as f:
            dict=json.load(f)
    (client_socket, f) = handshake.handshake(client_socket, f, dict["server"]["host"], dict["server"]["port"], "GREAT_I_AM_SUB_SERVER")
    while True:
        data = client_socket.recv(1024)
        if not data:
            print("Uh-oh server gone")
            ip_address = socket.gethostbyname(socket.gethostname())
            print(f"{ip_address}:{client_socket.getsockname()[1]}")
            if f"{ip_address}:{client_socket.getsockname()[1]}" == toprint[0]:
                print(f"This server ({ip_address}:{client_socket.getsockname()[1]}) is getting promoted to chief! All further requests will be forwarded here.")
                import server
                server.startfs("test", True, filedict)
                server.start_server()
            else:
                print("We have lost the main server, but we aren't being promoted. Restarting this instance to point to the main.")
                info = toprint[0].split(":")
                time.sleep(2)
                connect(info[0], info[1])
        client = list(pickle.loads(f.decrypt(data)))
        filedict = dict(client[0][0])
        print(filedict)
        client_socket.send(f.encrypt(bytes(handshake.GrabData(client, filedict), 'utf-8')))
        toprint=[]
        for x in client[0][1]:
                host = [value for key, value in x if key=='host'][0]
                ports = [value for key, value in x if key=='port'][0]
                toprint.append(f"{host}:{ports}")
        print(f"{client[1:]}, responded to server with {handshake.GrabData(client, filedict)} (even though it isn't listening). Btw, here are all the servers: {toprint}")
        
connect()

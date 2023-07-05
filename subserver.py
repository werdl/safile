import socket,sys
import os
import time
import pickle
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import handshake
filedict={}
def connect(ip,port):
    client_socket=""
    f=""
    (client_socket,f)=handshake.handshake(client_socket,f,'localhost',12345,"GREAT_I_AM_SUB_SERVER")
    while True:
        data = client_socket.recv(1024)
        if not data:
            print("Uh-oh server gone")
            import server
            server.startfs("test",True,filedict)
            server.start_server()
        client = list(pickle.loads(f.decrypt(data)))
        filedict=client[0]["filedict"]
        client_socket.send(f.encrypt(bytes(handshake.GrabData(client,filedict),'utf-8')))
        print(f"{client[1:]}, responded to server with {handshake.GrabData(client,filedict)} (even though it isn't listening)")
connect(sys.argv[1],sys.argv[2])
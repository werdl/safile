import socket
import dill as pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)
    client_socket.connect(server_address)
    pub_key = client_socket.recv(1024)
    pub_key = load_pem_public_key(pub_key, backend=default_backend())
    
    encrypted_password = pub_key.encrypt(
        b"lel",
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send(encrypted_password)
    response = client_socket.recv(1024).decode('utf-8')
    print('Response from server:', response)
    while True:
        message = input("Enter a command: ")
        tosend = message.split(" ")
        tosend.insert(0, "password")
        client_socket.send(pickle.dumps(tosend))
        response = client_socket.recv(1024).decode('utf-8')
        print('Response from server:', response)
    client_socket.close()

start_client()

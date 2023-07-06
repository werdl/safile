import socket,sys,time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.fernet import Fernet
def handshake(client_socket,f,ip,port,msg: str="GREAT_I_AM_CLIENT",delay=0):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip,port)
    print(server_address)
    time.sleep(delay)
    client_socket.connect(server_address)
    pub_key = client_socket.recv(1024)
    pub_key = load_pem_public_key(pub_key, backend=default_backend())
    encrypted_password = pub_key.encrypt(
        b"somecryptographicallysecurepassword",
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send(encrypted_password)
    response = client_socket.recv(1024).decode('utf-8')
    print('Response from server:', response)
    if response!="PASS":
        sys.exit(-1)
    client_socket.send(msg.encode('utf-8'))
    my_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    my_pub_key = my_priv_key.public_key()
    if client_socket.recv(1024).decode('utf-8')!="KEY":
        print("Handshake failed at KEY")
        sys.exit(1)
    my_pub_bytes=my_pub_key.public_bytes(Encoding.PEM, PublicFormat.PKCS1)
    client_socket.send(my_pub_bytes)
    response=client_socket.recv(4096)
    plainresponse=my_priv_key.decrypt(
        response,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send("DONE".encode('utf-8'))
    f = Fernet(plainresponse)
    return (client_socket,f)
def GrabData(client: list,filedict:dict) -> str:
    if client[1] == "grab":
        if client[2] in filedict:
            return filedict[client[2]]
        else:
            return "That file doesn't exist on the server."
    elif client[1] == "change":
        with open(dir + "/" + client[2], "w") as f:
            f.write(client[3])
        return "Done"
    elif client[1] == "del":
        os.remove(dir + "/" + client[2])
        return "Gone"
    elif client[1]=="help":
        return """
~~~~~~~~~~~~~~~~~~~
SaFile server help:
~~~~~~~~~~~~~~~~~~~
- grab <file>
returns content of <file>

- change <file> <data>
writes <data> to <file>, can create file

- del <file>
deletes file

- help
shows this menu
"""
    else:
        return f"This server doesn't recognise `{' '.join(client[1:])}` as a command."
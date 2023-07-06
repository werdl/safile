import socket
import os
import time
import pickle
import threading
import sys,cmd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import handshake

subservers=[]
symmetrickey=Fernet.generate_key()

def handle_client(client_socket):
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pub_key = priv_key.public_key()
    client_socket.send(pub_key.public_bytes(Encoding.PEM, PublicFormat.PKCS1))
    response = client_socket.recv(1024)
    if priv_key.decrypt(
        response,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8') == "somecryptographicallysecurepassword":
        client_socket.send("PASS".encode('utf-8'))
        res=client_socket.recv(1024).decode('utf-8')
        if res=="GREAT_I_AM_CLIENT":
            client_socket.send("KEY".encode('utf-8'))
            client_pub_key=load_pem_public_key(client_socket.recv(1024),default_backend())
            f=Fernet(symmetrickey)
            encrypted_key = client_pub_key.encrypt(
                symmetrickey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_key)
            res=client_socket.recv(1024)
            if res.decode('utf-8')=="DONE":
                print("Connection established")
            while True:
                data = client_socket.recv(1024)
                for client in subservers:
                    clienttempdata = list(pickle.loads(f.decrypt(data)))
                    pickledsubs=set()
                    for sub in subservers:
                        host, port = sub.getpeername()
                        pickledsubs.add(tuple({"host": host, "port": port}.items()))
                    pickledsubs=set(pickledsubs)
                    print(pickledsubs)
                    clienttempdata[0]=[filedict,pickledsubs]
                    
                    client.send(f.encrypt(pickle.dumps(clienttempdata)))
                    _temp=client.recv(1024)
                if not data:
                    break
                client = list(pickle.loads(f.decrypt(data)))
                client_socket.send(f.encrypt(((handshake.GrabData(client,filedict)).encode('utf-8')+"<~SAFILEPACKET~>".encode('utf-8')+(pickle.dumps({"filedict":filedict,"subservers":pickledsubs})))))
            client_socket.close()
        elif res=="GREAT_I_AM_SUB_SERVER":
            client_socket.send("KEY".encode('utf-8'))
            client_pub_key=load_pem_public_key(client_socket.recv(1024),default_backend())
            f=Fernet(symmetrickey)
            encrypted_key = client_pub_key.encrypt(
                symmetrickey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_key)
            res=client_socket.recv(1024)
            if res.decode('utf-8')=="DONE":
                print(f"Connection established withsub server")
            subservers.append(client_socket)
    else:
        client_socket.send("FAIL".encode('utf-8'))
        client_socket.close()

filelist = []
dir = ""
filedict = {}
checkfiles=True

def startfs(dirr,starting=None,filedictt=None):
    global filelist, dir, filedict
    if starting!=None:
        checkfiles=False
        filedict=filedictt
    dir = dirr

def start_server(host='localhost'):
    global filelist
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    server_address = (host, 12345)
    server_socket.bind(server_address)
    server_socket.listen(8)

    def listl(dirr):
        global filelist, filedict
        while True:
            time.sleep(1)
            if checkfiles:
                filelist = os.listdir(dirr)
                for file in filelist:
                    with open(os.path.join(dirr, file)) as f:
                        contents = f.readlines()
                        actual = ""
                        for x in contents:
                            actual += x
                    filedict[file] = actual 
                copy = dict(filedict)
                for key in copy:
                    if key not in filelist:
                        del filedict[key]

    listthread = threading.Thread(target=listl, args=(dir,))
    listthread.start()

class SafileConsole(cmd.Cmd):
    intro = "Welcome to your safile server! Enjoy."
    prompt = "~~>"
    def do_start(self,arg):
        """Start the Safile server."""
        start_server_thread = threading.Thread(target=start_server)
        start_server_thread.start()
        print("Safile server started.")
    def do_ls(self,arg):
        """List the files in the file server."""
        print(f"Files in the file server: ")
        for key,val in filedict:
            print(key+":"+val)
    def do_lssubs(self,arg):
        """List the connected sub-servers."""
        print("Connected sub-servers:")
        for i, subserver in enumerate(subservers):
            host, port = subserver.getpeername()
            print(f"Sub-server {i+1}: {host}:{port}")
    def do_check(self,arg):
        """Check if we are running"""
        if filedict!={}:
            print("Server is running")
        else:
            print("Server? What server?")
    def do_quitsub(self, arg):
        """Quit the current connection."""
        if arg:
            try:
                subserver_index = int(arg)
                if 0 < subserver_index <= len(subservers):
                    subserver = subservers[subserver_index - 1]
                    subserver.close()
                    del subservers[subserver_index - 1]
                    print(f"Sub-server {subserver_index} disconnected.")
                else:
                    print("Invalid sub-server index.")
            except ValueError:
                print("Invalid sub-server index.")
        else:
            print("Please provide a sub-server index.")

    def do_exit(self, arg):
        """Exit the Safile console."""
        print("Exiting the Safile console...")
        sys.exit()
    def do_help(self, arg):
        """List available commands or provide help for a specific command."""
        if arg:
            try:
                func = getattr(self, 'do_' + arg)
                print(func.__doc__)
            except AttributeError:
                print("Invalid command.")
        else:
            print("Available commands:")
            commands = [cmd[3:] for cmd in dir(self) if cmd.startswith('do_')]
            print(", ".join(commands))
startfs("test")
console = SafileConsole()
console.cmdloop()
# start_server()
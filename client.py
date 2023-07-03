import pickle
import handshake
def start_client():
    client_socket=""
    f=""
    (client_socket,f)=handshake.handshake(client_socket,f)
    while True:
        message = input("Enter a command: ")
        tosend = message.split(" ")
        tosend.insert(0, "password")
        client_socket.send(f.encrypt(pickle.dumps(tosend)))
        response = client_socket.recv(1024)
        response=(f.decrypt(response)).decode('utf-8')
        print('Response from server:', response)
    client_socket.close()
start_client()
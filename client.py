import pickle
import handshake
def start_client():
    client_socket=""
    f=""
    response="a"
    (client_socket,f)=handshake.handshake(client_socket,f,'localhost',12345)
    while True:
        message = input("Enter a command: ")
        tosend = message.split(" ")
        tosend.insert(0, "password")
        client_socket.send(f.encrypt(pickle.dumps(tosend)))
        responseraw = client_socket.recv(1024)
        response=(f.decrypt(pickle.loads(responseraw)))[1]
        print("server gone")
        print(response[0])
        print('Response from server:', response)
    client_socket.close()
start_client()
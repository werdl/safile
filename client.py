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
        responseraw = client_socket.recv(4096)
        if not responseraw:
            print("Server gone")
            print(response[0])
        response = f.decrypt(responseraw)
        try:
            response_str = response.decode('utf-8')
        except UnicodeDecodeError:
            response_str = response  # Treat it as raw bytes

        procres = response_str.split(b"<~SAFILEPACKET~>")
        print('Response from server:', procres[0].decode('utf-8'))
        subserver_list = pickle.loads(procres[1])
        print('Current subserver list:', dict(subserver_list["subservers"]))
    client_socket.close()
start_client()
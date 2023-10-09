import pickle,time,json
import handshake

def start_client(prevjustent: bool,pev: str):
    client_socket = ""
    f = ""
    response = "a"
    toprint = []
    prevjustsent=prevjustent
    prev=pev

    if os.path.isfile("config.json"):
        with open("config.json","r") as f:
            dict=json.load(f)
    (client_socket, f) = handshake.handshake(client_socket, f, dict["server"]["host"], dict["server"]["port"])
    
    while True:
        if not prevjustsent:
            message = input("Enter a command: ")
        else:
            message=prev
            prevjustsent=False
            prev=""
        tosend = message.split(" ")
        tosend.insert(0, "password")
        client_socket.send(f.encrypt(pickle.dumps(tosend)))
        
        responseraw = client_socket.recv(4096)
        if not responseraw:
            print("Server gone")
            print(f"With the server gone, control has been delegated to the first subserver at {toprint[0]}. Redirecting control there...")
            start_client(True,message)
            # client_socket.close()
            # info = toprint[0].split(":")
            # print(info)
            # print(f"handshake.handshake({client_socket}, {f}, {info[0]}, {int(info[1])},{3})")
            # time.sleep(3)

            # (client_socket, f) = handshake.handshake(client_socket, f, ip='localhost',port=12345)
        response = f.decrypt(responseraw)
        try:
            response_str = response.decode('utf-8')
        except UnicodeDecodeError:
            response_str = response  # Treat it as raw bytes
        procres = response_str.split(b"<~SAFILEPACKET~>")
        print('Response from server:', procres[0].decode('utf-8'))
        
        subserver_list = pickle.loads(procres[1])
        toprint = []
        
        if subserver_list:
            subservers = subserver_list["subservers"]
            
            if subservers:
                print("Current subserver list:")
                for subserv in subservers:
                    host = [value for key, value in subserv if key == 'host'][0]
                    port = [value for key, value in subserv if key == 'port'][0]
                    subserv_str = f"{host}:{port}"
                    toprint.append(subserv_str)
                    print(subserv_str)
            else:
                print("No subservers available.")
        else:
            print("No subserver list available.")
    
    client_socket.close()

start_client(False,"")

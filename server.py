import socket, threading, pyDHE, time, sys

host = '0.0.0.0'
port = 7976

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(2)
print("Waiting for connection from the client...")

clients = []
nicknames = []


def broadcast(message):
    for client in clients:
        time.sleep(0.3)
        client.send(message)


def handle(client):                                         
    while True:
        try:
            message = client.recv(2048)
            broadcast(message)
        except:
            print("NUMBER OF CLIENTS IN LIST:", len(clients))
            # if there is error sending message to client, means disconnected, remove all client connection
            print("Someone disconnected, terminating all sessions!")
            for client in clients:
                client.close()
            clients.clear()
            nicknames.clear()
            break


def receive():
    while True:
        try:
            client, address = server.accept()
            clients.append(client)
            if len(clients) > 2:
                client.send('Chat room full.'.encode('utf-8'))
                client.close()
                clients.pop()
            else:
                print("Connected with {}".format(str(address)))       
                client.send('NICKNAME'.encode('utf-8'))
                nickname = client.recv(2048).decode('utf-8')
                nicknames.append(nickname)
                
                print("Nickname is {}".format(nickname))
                broadcast("{} joined! ".format(nickname).encode('utf-8'))
                client.send('Connected to server!'.encode('utf-8'))
                
                if len(clients) == 2:
                    broadcast('EXCHANGE'.encode('utf-8'))
                    
                thread = threading.Thread(target=handle, args=(client,))
                thread.daemon = True
                thread.start()

                c_alive = threading.Timer(180.0, check_alive)
                c_alive.daemon = True
                c_alive.start()

        except KeyboardInterrupt:
            print("\nExiting...!")
            exit_program()
            break


def exit_program():
    server.close()
    time.sleep(1)
    sys.exit()


def check_alive():
    try:
        broadcast('ALIVE'.encode('utf-8'))
    except KeyboardInterrupt:
        print("\nExiting...")
        exit_program()
    except:
        pass

try:
    receive() 
except KeyboardInterrupt:
    exit_program()

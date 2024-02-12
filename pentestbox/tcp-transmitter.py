import socket

def send_message(ip, port, message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip, port))
    client_socket.sendall(message.encode())

    response = client_socket.recv(1024)
    print(f"Received: {response.decode()}")

    client_socket.close()

# Send a message
server_ip = '192.168.0.3'
server_port = 12345
message = "Hello, Server!"
send_message(server_ip, server_port, message)

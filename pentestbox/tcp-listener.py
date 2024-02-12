import socket

def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(1)
    print(f"Listening on {ip}:{port}")

    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        print(f"Received: {data.decode()}")
        client_socket.sendall(data)

    client_socket.close()
    server_socket.close()

# Run the server
server_ip = '192.168.0.3'
server_port = 12345
start_server(server_ip, server_port)

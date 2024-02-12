import socket

def start_udp_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip, port))
    print(f"UDP Server listening on {ip}:{port}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        if not data:
            break
        print(f"Received: {data.decode()} from {client_address}")
        server_socket.sendto(data, client_address)

    server_socket.close()

# Run the server
server_ip = '192.168.0.3'
server_port = 12345
start_udp_server(server_ip, server_port)

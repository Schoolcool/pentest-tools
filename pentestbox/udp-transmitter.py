import socket

def send_udp_data(ip, port, message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send data
        client_socket.sendto(message.encode(), (ip, port))
        print(f"Sent: {message} to {ip}:{port}")

        # Receive response
        data, server = client_socket.recvfrom(1024)
        print(f"Received: {data.decode()} from {server}")

    finally:
        client_socket.close()

# Example usage
server_ip = '192.168.0.3'
server_port = 12345
message = "Hello, UDP Server!"
send_udp_data(server_ip, server_port, message)

import socket
import time

import protocol
import threading
import multiprocessing
import scapy.all as scapy


class HoneypotServer:
    def __init__(self):
        self.server_ip = "0.0.0.0"
        self.server_port = 8080
        self.server_addr = (self.server_ip, self.server_port)

        self.server_socket = socket.socket()
        self.server_socket.bind(self.server_addr)
        self.server_socket.listen()
        print("server is up and running")
        self.clients = {}  # key: client_address value: [client_socket, client_mac, client_mac, spoof_ip, Connected]

    def accept_connection(self):
        client_socket, (client_ip, client_port) = self.server_socket.accept()
        print(f"connection from {client_ip}")
        client_mac, spoof_ip = protocol.recv_data(client_socket).decode().split("-")
        self.clients[client_ip] = [client_socket, client_port, client_mac, spoof_ip, True]
        self.recv(client_ip)

    def start_honeypot(self):
        ip = "127.0.0.1"
        # threading.Thread(target=self.recv, args=ip, daemon=True).start()
        while self.clients[ip][4]:
            packet = scapy.ARP(op=2, pdst=ip, hwdst=self.clients[ip][2], psrc=self.clients[ip][3])
            scapy.send(packet, verbose=False)
            time.sleep(2)

    def recv(self, ip):
        p = threading.Thread(target=self.start_honeypot, daemon=True)
        p.start()
        client_socket = self.clients[ip][0]
        while True:
            try:
                protocol.recv_data(client_socket).decode()
            except Exception:
                self.clients[ip][4] = False
                break


def main():
    try:
        hps = HoneypotServer()
        hps.accept_connection()
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
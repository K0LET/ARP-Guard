import socket
import scapy.all as scapy
from scapy.all import conf
import threading
import protocol


class Client:
    def __init__(self, server_ip="127.0.0.1", spoof_ip="0.0.0.0"):
        self.server_ip = server_ip
        print(self.server_ip)
        self.server_port = 8080
        self.server_addr = (self.server_ip, self.server_port)
        self.client_socket = socket.socket()

        self.ip = scapy.get_if_addr(conf.iface)
        self.my_mac = self.get_mac()

        self.spoof_ip = spoof_ip

    def get_mac(self):
        """
        :return: the mac address that belongs to the ip
        :rtype: str
        """
        try:
            arp_request = scapy.ARP(pdst=self.ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            print("ip addr is not in lan")

    def connect_to_server(self):
        self.client_socket.connect(self.server_addr)
        print("connected")
        protocol.send_data(self.client_socket, f"{self.my_mac}-{self.spoof_ip}".encode())
        self.send_to_server()

    def send_to_server(self):
        while True:
            protocol.send_data(self.client_socket, b"")


def main():
    try:
        c = Client()
        c.connect_to_server()
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()

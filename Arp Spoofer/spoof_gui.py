"""
created by Yoav Kolet
"""

import re
import time
import win32api
import win32con
import threading
import SpoofTools
import customtkinter
from tkinter import *
import multiprocessing
import scapy.all as scapy
from scapy.all import conf
from ARPSpoofer import ArpSpoofing


"""
THIS CODE IS FOR LEARNING PURPOSES ONLY!
"""


class SpoofGui:
    def __init__(self):
        # window
        self.root = customtkinter.CTk()
        self.set_window()

        # widgets
        # self.spoof_bt = None
        # self.show_ips_bt = None
        # self.input = None
        # self.not_valid = None
        # self.switch = None
        # self.show_ips_window = None
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
            threading.Thread(target=self.display_not_valid, daemon=True).start()
        else:
            self.show_warning("This program is for learning purposes only!", "ARP Spoofer Warning")
            self.spoof = ArpSpoofing(self.input.get())
            p = multiprocessing.Process(target=self.spoof.start_spoof, daemon=True)
            p.start()
            self.draw_details()

    def display_not_valid(self):
        not_valid = customtkinter.CTkLabel(master=self.root,
                                           text="not valid",
                                           text_color="red",
                                           compound=CENTER,
                                           font=self.get_font())
        not_valid.place(relx=0.5, rely=0.6, anchor=CENTER)
        time.sleep(2)
        not_valid.place_forget()

    @staticmethod
    def make_toplevel_spoof():
        tl = customtkinter.CTkToplevel()
        tl.title("ARP Spoofer")
        tl.iconbitmap("assets//spoof_icon.ico")
        tl.geometry("700x500")
        return tl

    def draw_details(self):
        tl = self.make_toplevel_spoof()
        customtkinter.CTkSwitch(master=tl,
                                text="Forward packets",
                                command=self.switch_event,
                                variable=customtkinter.StringVar(self.root, value="on"),
                                onvalue="on",
                                offvalue="off",
                                progress_color="red").place(relx=0.5, rely=0.9, anchor=CENTER)
        customtkinter.CTkLabel(tl, text="your pc:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.1)
        customtkinter.CTkLabel(tl, text=f"ip: {self.spoof.ip} mac: {self.spoof.my_mac}"
                               , font=self.get_font()).place(relx=0.15, rely=0.21)
        customtkinter.CTkLabel(tl, text="victim:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.32)
        customtkinter.CTkLabel(tl, text=f"ip: {self.spoof.victim_ip} mac: {self.spoof.victim_mac}"
                               , font=self.get_font()).place(relx=0.15, rely=0.43)
        customtkinter.CTkLabel(tl, text="gateway:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.54)
        customtkinter.CTkLabel(tl, text=f"ip: {self.spoof.gateway_ip} mac: {self.spoof.gateway_mac}"
                               , font=self.get_font()).place(relx=0.15, rely=0.65)

    def display_ips(self):
        if not self.show_ips_flag:
            ip = scapy.get_if_addr(conf.iface).split(".")
            ip[-1] = "0"
            ip_list = SpoofTools.send_arp_broadcast(".".join(ip) + "/24")
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


def main():
    sg = SpoofGui()
    sg.root.mainloop()


if __name__ == '__main__':
    main()

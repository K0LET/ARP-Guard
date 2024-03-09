import threading
import time
from tkinter import *
import customtkinter
import Tools


class GUI:
    def __init__(self):
        # window
        self.root = customtkinter.CTk()
        self.set_window()
        self.font = customtkinter.CTkFont(size=25)
        self.sd = Tools.SpoofDetector()

        # widgets
        self.clear_arp = None
        self.get_arp = None
        self.detect_spoof = None
        self.detect_spoof_overlay = None
        self.spoof_label = None
        self.no_spoof_label = None
        self.switch = None
        self.set_widgets()
        self.place_widgets()

        self.sd.overlay = False
        self.show_arp_flag = False
        self.arp_cache = None
        self.root.mainloop()

    def set_widgets(self):
        self.clear_arp = customtkinter.CTkButton(master=self.root,
                                                 text="Clear ARP cache",
                                                 width=250,
                                                 height=70,
                                                 font=self.font,
                                                 command=Tools.run_as_admin)

        self.get_arp = customtkinter.CTkButton(master=self.root,
                                               text="Get ARP cache",
                                               width=250,
                                               height=70,
                                               font=self.font,
                                               command=self.show_arp_cache)

        self.detect_spoof = customtkinter.CTkButton(master=self.root,
                                                    text="Detect Spoof",
                                                    width=250,
                                                    height=70,
                                                    font=self.font,
                                                    command=self.detect_mac)

        self.spoof_label = customtkinter.CTkLabel(master=self.root,
                                                  text="spoof detected from:",
                                                  text_color="red",
                                                  font=self.font)

        self.no_spoof_label = customtkinter.CTkLabel(master=self.root,
                                                     text=f"no spoof detected",
                                                     text_color="green",
                                                     font=self.font)

        self.detect_spoof_overlay = customtkinter.CTkLabel(self.root,
                                                           text="Detect Spoof",
                                                           fg_color="gray",
                                                           text_color="black",
                                                           corner_radius=5,
                                                           width=250,
                                                           height=70,
                                                           font=self.font)

        self.switch = customtkinter.CTkSwitch(master=self.root,
                                              text="Run in the background",
                                              command=self.switch_event,
                                              variable=customtkinter.StringVar(self.root, value="off"),
                                              onvalue="on",
                                              offvalue="off")

    def set_window(self):
        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("dark-blue")
        self.root.title("ARP Guard")
        self.root.iconbitmap("assets//icon.ico")
        self.root.geometry("800x700")

    def place_widgets(self):
        self.clear_arp.place(relx=0.5, rely=0.3, anchor=CENTER)
        self.get_arp.place(relx=0.5, rely=0.5, anchor=CENTER)
        self.detect_spoof.place(relx=0.5, rely=0.7, anchor=CENTER)
        self.switch.place(relx=0.5, rely=0.77, anchor=CENTER)

    def switch_event(self):
        if not self.sd.overlay:
            self.sd.overlay = True
            threading.Thread(target=self.detect_mac_overlay, daemon=True).start()
            self.detect_spoof.place_forget()
            self.detect_spoof_overlay.place(relx=0.5, rely=0.7, anchor=CENTER)
        else:
            self.sd.overlay = False
            self.detect_spoof_overlay.place_forget()
            self.detect_spoof.place(relx=0.5, rely=0.7, anchor=CENTER)

    def detect_mac(self):
        flag, ips = self.sd.detect_mac()
        if len(ips) > 1:
            pass
        elif len(ips) == 1:
            self.no_spoof_label.place_forget()
            self.spoof_label.place(relx=0.5, rely=0.825, anchor=CENTER)
            customtkinter.CTkLabel(master=self.root,
                                   text=f"{ips[0]} : {self.sd.ip_mac_dict[ips[0]]}",
                                   text_color="red",
                                   font=self.font).place(relx=0.5, rely=0.9, anchor=CENTER)
        else:
            self.spoof_label.place_forget()
            self.no_spoof_label.place(relx=0.5, rely=0.825, anchor=CENTER)

    def detect_mac_overlay(self):
        while self.sd.overlay:
            self.detect_mac()
            time.sleep(1)

    def show_arp_cache(self):
        if not self.show_arp_flag:
            self.show_arp_flag = True
            self.arp_cache = customtkinter.CTkToplevel()
            self.arp_cache.resizable(width=False, height=False)
            self.arp_cache.title("ARP Cache")
            my_frame = customtkinter.CTkScrollableFrame(self.arp_cache, width=600, height=500)
            customtkinter.CTkLabel(my_frame, text=Tools.get_arp_cache(), font=customtkinter.CTkFont(size=25),
                                   text_color="white").pack()
            my_frame.pack()
            self.arp_cache.mainloop()
        else:
            if self.arp_cache:
                self.show_arp_flag = False
                self.arp_cache.destroy()
                self.show_arp_cache()


def main():
    GUI()


if __name__ == '__main__':
    main()


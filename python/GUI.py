from tkinter import *
import customtkinter
import Tools


class GUI:
    def __init__(self):
        self.root = customtkinter.CTk()
        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("dark-blue")
        self.root.title("ARP Guard")
        self.root.iconbitmap("assets//icon.ico")
        self.root.geometry("800x700")
        self.font = customtkinter.CTkFont(size=25)
        self.sd = Tools.SpoofDetector()
        self.clear_arp = customtkinter.CTkButton(master=self.root,
                                                 text="Clear ARP cache",
                                                 width=250,
                                                 height=70,
                                                 font=self.font,
                                                 command=Tools.run_as_admin)
        self.clear_arp.place(relx=0.5, rely=0.3, anchor=CENTER)
        self.get_arp = customtkinter.CTkButton(master=self.root,
                                               text="Get ARP cache",
                                               width=250,
                                               height=70,
                                               font=self.font,
                                               command=Tools.run_cmd)
        self.get_arp.place(relx=0.5, rely=0.5, anchor=CENTER)
        self.detect_spoof = customtkinter.CTkButton(master=self.root,
                                                    text="Detect Spoof",
                                                    width=250,
                                                    height=70,
                                                    font=self.font,
                                                    command=self.sd.detect_mac)
        self.detect_spoof.place(relx=0.5, rely=0.7, anchor=CENTER)
        self.root.mainloop()


GUI()

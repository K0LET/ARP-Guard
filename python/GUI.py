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
                                               command=self.show_arp_cache)
        self.get_arp.place(relx=0.5, rely=0.5, anchor=CENTER)
        self.detect_spoof = customtkinter.CTkButton(master=self.root,
                                                    text="Detect Spoof",
                                                    width=250,
                                                    height=70,
                                                    font=self.font,
                                                    command=self.sd.detect_mac)
        self.detect_spoof.place(relx=0.5, rely=0.7, anchor=CENTER)

        self.show_arp_flag = False
        self.arp_cache = None
        self.root.mainloop()

    def show_arp_cache(self):
        if not self.show_arp_flag:
            self.show_arp_flag = True
            self.arp_cache = customtkinter.CTkToplevel()
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


GUI()

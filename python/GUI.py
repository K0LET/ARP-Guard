from tkinter import *
import customtkinter


class GUI:
    def __init__(self):
        self.root = customtkinter.CTk()
        customtkinter.set_default_color_theme("dark-blue")
        self.root.title("ARP Guard")
        self.root.iconbitmap("assets//icon.ico")
        self.root.geometry("800x700")
        self.font = customtkinter.CTkFont(size=25)
        self.clear_arp = customtkinter.CTkButton(master=self.root, text="Clear ARP cache", width=250, height=75, font=self.font)
        self.clear_arp.place(relx=0.5, rely=0.4, anchor=CENTER)
        self.get_arp = customtkinter.CTkButton(master=self.root, text="Get ARP cache", width=250, height=75, font=self.font)
        self.get_arp.place(relx=0.5, rely=0.6, anchor=CENTER)
        self.root.mainloop()


GUI()

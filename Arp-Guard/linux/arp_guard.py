"""
created by Yoav Kolet
"""
import sys
import threading
import time
from tkinter import *

import customtkinter
from PIL import Image

import tools
from toplevels import ARPCacheTopLevel, SpoofDetectedTopLevel, InfoToplevel


class GUI:
    def __init__(self):
        # window
        self.root = customtkinter.CTk()
        self.set_window()
        self.font = customtkinter.CTkFont(size=25)
        self.sd = tools.SpoofDetector()
        self.driver_path = "driver/driver.ko"

        # widgets
        self.clear_arp = None
        self.get_arp = None
        self.detect_spoof = None
        self.show_spoof_bt = None
        self.detect_spoof_overlay = None
        self.spoof_label = None
        self.no_spoof_label = None
        self.switch = None
        self.clear_arp_label = None
        self.empty_label = None
        self.toplevel = None
        self.sd.overlay = False

        self.arp_toplevel = ARPCacheTopLevel()
        self.info = InfoToplevel(self.sd, self.driver_path)
        self.sd_toplevel = SpoofDetectedTopLevel(self.sd, self.driver_path, self.info)

    def start_gui(self):
        self.set_widgets()
        self.place_widgets()
        self.start_detect_stop_spoof()
        self.root.mainloop()

    def set_widgets(self):
        """
        Set up the widgets for the GUI.

        This method initializes various buttons, labels, and switches for the GUI.
        """
        # Buttons
        self.clear_arp = customtkinter.CTkButton(master=self.root,
                                                 text="Clear ARP cache",
                                                 bg_color="black",
                                                 width=250,
                                                 height=70,
                                                 font=self.font,
                                                 command=self.clear_mac_cache)

        self.get_arp = customtkinter.CTkButton(master=self.root,
                                               text="Get ARP cache",
                                               bg_color="black",
                                               width=250,
                                               height=70,
                                               font=self.font,
                                               command=self.arp_toplevel.set_arp_toplevel)

        self.detect_spoof = customtkinter.CTkButton(master=self.root,
                                                    text="Detect Spoof",
                                                    bg_color="black",
                                                    width=250,
                                                    height=70,
                                                    font=self.font,
                                                    command=self.detect_mac)

        self.show_spoof_bt = customtkinter.CTkButton(master=self.root,
                                                     text="show spoof details",
                                                     bg_color="black",
                                                     fg_color="darkred",
                                                     hover_color="red",
                                                     width=150,
                                                     height=30,
                                                     command=self.sd_toplevel.set_spoof_detected_toplevel)

        # Labels
        customtkinter.CTkButton(self.toplevel,
                                height=37,
                                width=37,
                                bg_color="black",
                                text="i",
                                font=self.font,
                                command=self.info.set_info_toplevel
                                ).place(relx=0.1, rely=0.1, anchor=CENTER)

        self.spoof_label = customtkinter.CTkLabel(master=self.root,
                                                  text="spoof detected!",
                                                  text_color="red",
                                                  bg_color="black",
                                                  font=self.font)

        self.no_spoof_label = customtkinter.CTkLabel(master=self.root,
                                                     text="No Spoof Detected",
                                                     text_color="green",
                                                     bg_color="black",
                                                     font=self.font)

        self.clear_arp_label = customtkinter.CTkLabel(master=self.root,
                                                      text="ARP Cache Cleared",
                                                      text_color="green",
                                                      bg_color="black",
                                                      font=self.font)

        self.empty_label = customtkinter.CTkLabel(master=self.root,
                                                  text="ARP Cache Is Empty",
                                                  text_color="green",
                                                  bg_color="black",
                                                  font=self.font)

        self.detect_spoof_overlay = customtkinter.CTkLabel(self.root,
                                                           text="Detect Spoof",
                                                           fg_color="gray",
                                                           text_color="black",
                                                           corner_radius=5,
                                                           width=250,
                                                           height=70,
                                                           bg_color="black",
                                                           font=self.font)

        self.switch = customtkinter.CTkSwitch(master=self.root,
                                              text="Run in the background",
                                              command=self.switch_event,
                                              variable=customtkinter.StringVar(self.root, value="off"),
                                              onvalue="on",
                                              bg_color="black",
                                              offvalue="off")

    def clear_mac_cache(self):
        """
        Clear the ARP cache.

        This method clears the ARP cache using the `clear_mac_cache` method from the `Tools` class.
        It starts a new thread to display a label indicating that the ARP cache has been cleared.

        """
        tools.clear_mac_cache()
        threading.Thread(target=self.place_arp_cleared_label).start()

    def place_arp_cleared_label(self):
        """
        Place the ARP cache cleared label.

        This method places the ARP cache cleared label on the GUI window.
        It then waits for 1.2 seconds before removing the label.

        """
        self.clear_arp_label.place(relx=0.25, rely=0.15, anchor=CENTER)
        time.sleep(1.2)
        self.clear_arp_label.place_forget()

    def set_window(self):
        """
        Set up the appearance and size of the main window.

        This method configures the appearance mode and color theme of the GUI.

        """
        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("dark-blue")
        self.root.title("ARP Guard")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        image = Image.open("assets//jedi_bg.png")
        background_image = customtkinter.CTkImage(image, size=(900, 600))

        bg_lbl = customtkinter.CTkLabel(self.root, text="", image=background_image)
        bg_lbl.place(x=0, y=0)

    def place_widgets(self):
        """
        Place the buttons and switch widgets on the main window.
        """
        self.clear_arp.place(relx=0.25, rely=0.25, anchor=CENTER)
        self.get_arp.place(relx=0.25, rely=0.45, anchor=CENTER)
        self.detect_spoof.place(relx=0.25, rely=0.65, anchor=CENTER)
        self.switch.place(relx=0.25, rely=0.75, anchor=CENTER)

    def switch_event(self):
        """
        Handle the switch event.

        This method is called when the state of the switch widget changes. If the
        switch is turned on, it starts the background thread to continuously detect
        ARP spoofing. If the switch is turned off, it stops the background thread
        and reverts to the regular detection mode.

        """
        if not self.sd.overlay:
            self.sd.overlay = True
            threading.Thread(target=self.detect_mac_overlay, daemon=True).start()
            self.detect_spoof.place_forget()
            self.detect_spoof_overlay.place(relx=0.25, rely=0.65, anchor=CENTER)
        else:
            self.sd.overlay = False
            self.detect_spoof_overlay.place_forget()
            self.detect_spoof.place(relx=0.25, rely=0.65, anchor=CENTER)

    def detect_mac(self):
        """
       Start ARP spoofing detection.

       This method starts a background thread to perform ARP spoofing detection.

       """
        t = threading.Thread(target=self.detect_mac_thread, daemon=True)
        t.start()

    def detect_mac_thread(self):
        """
        Perform ARP spoofing detection in a background thread.

        This method initiates ARP spoofing detection by calling the `detect_mac` method
        of the `SpoofDetector` object associated with the ARP Guard application. It handles
        the results of the detection process, updating the user interface accordingly.

        """
        ret = self.sd.detect_mac()
        if not ret:
            self.empty_label.place(relx=0.25, rely=0.825, anchor=CENTER)
            time.sleep(2)
            self.empty_label.place_forget()
            return

        flag, spoof_ips = ret
        if len(spoof_ips) >= 1:
            self.sd.spoofed = True

            for ip in spoof_ips:
                if ip not in self.sd.spoof_ips:
                    self.sd.spoof_ips.append(ip)

            self.no_spoof_label.place_forget()
            self.spoof_label.place(relx=0.25, rely=0.825, anchor=CENTER)
            self.show_spoof_bt.place(relx=0.25, rely=0.9, anchor=CENTER)

        elif not self.sd.overlay:
            self.show_spoof_bt.place_forget()
            self.empty_label.place_forget()
            self.spoof_label.place_forget()
            self.no_spoof_label.place(relx=0.25, rely=0.825, anchor=CENTER)
            time.sleep(2)
            self.no_spoof_label.place_forget()
            self.sd.spoofed = False

    def detect_mac_overlay(self):
        """
        Continuously perform ARP spoofing detection while the overlay flag is set.

        This method is intended to be executed in a background thread. It repeatedly calls
        the `detect_mac_thread` method to perform ARP spoofing detection, with a delay of 2 seconds
        between each detection attempt. The detection process continues as long as the `overlay`
        flag of the associated `SpoofDetector` object is set.

        """
        while self.sd.overlay:
            self.detect_mac()
            time.sleep(2)

    # def start_detect_stop_spoof(self):
    #     t = threading.Thread(target=self.detect_stop_spoof)
    #     t.start()
    #
    # def detect_stop_spoof(self):
    #     while not self.sd.detect_mac():
    #         time.sleep(1)
    #     self.show_spoof_bt.place_forget()
    #     self.spoof_label.place_forget()
    #     self.sd.spoofed = False
    #     self.detect_stop_spoof()


def main():
    try:
        if sys.platform == 'linux':
            gui = GUI()
            gui.start_gui()
        else:
            raise RuntimeError("Unsupported platform - try linux ubuntu")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()



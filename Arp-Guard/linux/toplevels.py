from tkinter import *
import customtkinter
import tools


class MyTopLevel:
    def __init__(self, size: str, resizable=(True, True)):
        self.toplevel = None
        self.title = "ARP Guard"
        self.resizable = (resizable[0], resizable[1])
        self.geometry = size
        self.enabled = False

    def set_top_level(self):  # , widgets: list[tuple]):
        """
        Create or destroy a top-level window based on the current state of the instance.

        If the top-level window is not currently enabled, this method creates a new top-level window with the specified
        title, resizable settings, and geometry. If the top-level window is already enabled, it destroys the existing
        window.
        """
        if not self.enabled:
            self.enabled = True
            self.toplevel = customtkinter.CTkToplevel()
            self.toplevel.title(self.title)
            self.toplevel.resizable(self.resizable[0], self.resizable[1])
            self.toplevel.geometry(self.geometry)
        else:
            self.enabled = False
            if self.toplevel:
                self.toplevel.destroy()
            self.set_top_level()


class ARPCacheTopLevel(MyTopLevel):
    def __init__(self):
        super().__init__("600x500", (False, False))

    def set_arp_toplevel(self):
        """
        Create a top-level window to display the ARP cache.

        This method creates a top-level window containing a scrollable frame to display the ARP cache retrieved using
        Tools.re_arp_cache().

        """
        self.set_top_level()
        frame = customtkinter.CTkScrollableFrame(self.toplevel,
                                                 width=600,
                                                 height=500)
        customtkinter.CTkLabel(frame,
                               text=tools.re_arp_cache(),
                               font=customtkinter.CTkFont(size=25),
                               text_color="white").pack()
        frame.pack()


class SpoofDetectedTopLevel(MyTopLevel):
    def __init__(self, spoof_detector, driver_path, info_toplevel):
        super().__init__("700x400", (False, False))
        self.font = customtkinter.CTkFont(size=25)
        self.driver_path = driver_path
        self.sd = spoof_detector
        self.info = info_toplevel

    def set_spoof_detected_toplevel(self):
        """
       Create a top-level window to display detected spoofed IP addresses.

       This method creates a top-level window containing buttons to run the filter driver and add a static entry,
        as well as a scrollable frame to display the detected spoofed IP addresses.

       """
        self.set_top_level()
        customtkinter.CTkFrame(self.toplevel, height=300, width=300, fg_color="gray").place(relx=0.15, rely=0.2)
        customtkinter.CTkButton(self.toplevel,
                                height=100,
                                width=100,
                                fg_color="green",
                                hover_color="darkgreen",
                                text="Run Filter Driver",
                                font=self.font,
                                command=self.run_driver
                                ).place(relx=0.8, rely=0.4, anchor=CENTER)
        customtkinter.CTkButton(self.toplevel,
                                height=100,
                                width=100,
                                fg_color="green",
                                hover_color="darkgreen",
                                text="Add Static Entry",
                                font=self.font,
                                command=self.static_entry_button
                                ).place(relx=0.8, rely=0.75, anchor=CENTER)
        customtkinter.CTkButton(self.toplevel,
                                height=37,
                                width=37,
                                text="i",
                                font=self.font,
                                command=self.info.set_info_toplevel
                                ).place(relx=0.9, rely=0.1, anchor=CENTER)
        scroll_frame = customtkinter.CTkScrollableFrame(self.toplevel, width=250, height=250, bg_color="grey")
        customtkinter.CTkLabel(scroll_frame,
                               text=self.sd.spoof_ip_to_str(),
                               text_color="white",
                               font=customtkinter.CTkFont(size=20)).pack(pady=10)
        customtkinter.CTkLabel(self.toplevel,
                               text="Spoof Detected from:",
                               text_color="white",
                               font=self.font).place(relx=0.1, rely=0.1)
        scroll_frame.place(relx=0.17, rely=0.25)

    def run_driver(self):
        """
        Run the filter driver.

        This method sets the driver status to active and attempts to load the filter driver into the kernel using
        insmod command with sudo privileges.

        """
        self.sd.spoofed = False
        self.info.driver_status = "active"
        cmd = ["sudo", "insmod", self.driver_path]
        tools.run_cmd(cmd)

    def static_entry_button(self):
        """
       Add a static ARP entry for the gateway IP and MAC address.

       This method sets the static status to active and adds a static ARP entry for the gateway IP and MAC address
       using the arp command with sudo privileges.

       """
        self.sd.spoofed = False
        self.info.static_status = "active"
        tools.run_cmd()
        ip = self.sd.gateway_ip
        mac = self.sd.gateway_mac
        cmd = ["sudo", "arp", "-s", ip, mac]
        tools.run_cmd(cmd)


class InfoToplevel(MyTopLevel):
    def __init__(self, spoof_detector, driver_path):
        super().__init__("500x250", (False, False))
        self.driver_path = driver_path
        self.sd = spoof_detector

        self.remove_driver_bt = None
        self.remove_static_entry_bt = None
        self.clear_database_bt = None
        self.remove_driver_overlay = None
        self.remove_static_entry_overlay = None
        self.clear_database_overlay = None

        self.font = customtkinter.CTkFont(size=20)

        self.driver_status = "not active"
        self.static_status = "not active"

    def set_info_toplevel(self):
        """
        Set up a top-level window to display driver and static entry information.

        This method sets up a top-level window to display information about the current status of the driver
        and static ARP entry. It also provides options to remove the driver and static entry.

        """
        self.set_top_level()
        self.check_active()
        customtkinter.CTkLabel(self.toplevel,
                               text="Driver: " + self.driver_status,
                               text_color="white",
                               font=customtkinter.CTkFont(size=20)).place(relx=0.25, rely=0.1, anchor=CENTER)
        customtkinter.CTkLabel(self.toplevel,
                               text="Static Entry: " + self.static_status,
                               text_color="white",
                               font=customtkinter.CTkFont(size=20)).place(relx=0.75, rely=0.1, anchor=CENTER)
        self.remove_driver_bt = customtkinter.CTkButton(self.toplevel,
                                                        height=70,
                                                        width=200,
                                                        fg_color="darkred",
                                                        hover_color="red",
                                                        text="Remove Driver",
                                                        font=self.font,
                                                        command=self.remove_driver)
        self.remove_static_entry_bt = customtkinter.CTkButton(self.toplevel,
                                                              height=70,
                                                              width=200,
                                                              fg_color="darkred",
                                                              hover_color="red",
                                                              text="Remove Static Entry",
                                                              font=self.font,
                                                              command=self.remove_static_entry)
        self.clear_database_bt = customtkinter.CTkButton(self.toplevel,
                                                         height=70,
                                                         width=200,
                                                         fg_color="darkred",
                                                         hover_color="red",
                                                         text="Clear Database",
                                                         font=self.font,
                                                         command=self.clear_database
                                                         )
        self.remove_driver_overlay = customtkinter.CTkLabel(self.toplevel,
                                                            text="Remove Driver",
                                                            fg_color="gray",
                                                            text_color="black",
                                                            corner_radius=5,
                                                            width=200,
                                                            height=70,
                                                            font=self.font)
        self.remove_static_entry_overlay = customtkinter.CTkLabel(self.toplevel,
                                                                  text="Remove Static Entry",
                                                                  fg_color="gray",
                                                                  text_color="black",
                                                                  corner_radius=5,
                                                                  width=200,
                                                                  height=70,
                                                                  font=self.font)
        self.clear_database_overlay = customtkinter.CTkLabel(self.toplevel,
                                                             text="Clear Database",
                                                             fg_color="gray",
                                                             text_color="black",
                                                             corner_radius=5,
                                                             width=200,
                                                             height=70,
                                                             font=self.font)
        self.check_overlay()

    def check_overlay(self):
        """
        Check the status of the driver, static entry and database and display corresponding overlay buttons.

        This method checks the status of the driver, static ARP entry and the database. Depending on the status,
        it displays overlay buttons for removing the driver, static entry or the database buttons.

        """
        if self.driver_status == "active":
            self.remove_driver_bt.place(relx=0.25, rely=0.5, anchor=CENTER)
        elif self.driver_status == "not active":
            self.remove_driver_overlay.place(relx=0.25, rely=0.5, anchor=CENTER)

        if self.static_status == "active":
            self.remove_static_entry_bt.place(relx=0.75, rely=0.5, anchor=CENTER)
        elif self.static_status == "not active":
            self.remove_static_entry_overlay.place(relx=0.75, rely=0.5, anchor=CENTER)

        self.sd.get_data()
        if self.sd.data != "":
            self.clear_database_bt.place(relx=0.5, rely=0.8, anchor=CENTER)
        else:
            self.clear_database_overlay.place(relx=0.5, rely=0.8, anchor=CENTER)

    def clear_database(self):
        self.sd.clear_data()
        self.clear_database_bt.place_forget()
        self.clear_database_overlay.place(relx=0.5, rely=0.8, anchor=CENTER)

    def check_active(self):
        """
        Check the status of the driver and static ARP entry.

        This method checks the status of the driver and static ARP entry by invoking appropriate methods
        from the `Tools` class. It updates the `driver_status` and `static_status` attributes accordingly.

        """
        static_bool = tools.check_static_arp(self.sd.gateway_ip)
        if static_bool:
            self.static_status = "active"
        else:
            self.static_status = "not active"

        driver_bool = tools.check_driver()
        if driver_bool:
            self.driver_status = "active"
        else:
            self.driver_status = "not active"

    def remove_driver(self):
        """
        Remove the driver and update its status.

        This method removes the driver by executing the appropriate command using the `Tools` class.
        It updates the `driver_status` attribute to indicate that the driver is not active anymore.
        It also handles the display of the remove driver button and overlay accordingly.

        """
        self.driver_status = "not active"
        cmd = ["sudo", "rmmod", self.driver_path]
        tools.run_cmd(cmd)
        self.remove_driver_bt.place_forget()
        self.remove_driver_overlay.place(relx=0.25, rely=0.5, anchor=CENTER)

    def remove_static_entry(self):
        """
        Remove the static ARP entry and update its status.

        This method removes the static ARP entry by executing the appropriate command via the `Tools` class.
        It updates the `static_status` attribute to indicate that the static entry is not active anymore.
        It also handles the display of the remove static entry button and overlay accordingly.

        """
        self.static_status = "not active"
        tools.run_cmd()
        ip = self.sd.gateway_ip
        cmd = ["sudo", "arp", "-d", ip]
        tools.run_cmd(cmd)
        self.remove_static_entry_bt.place_forget()
        self.remove_static_entry_overlay.place(relx=0.75, rely=0.5, anchor=CENTER)

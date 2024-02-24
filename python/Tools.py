from ctypes import *
import sys
import subprocess
import os
import re
from scapy.all import conf


def run_as_admin(command="arp -d"):
    """
    this function run a command in the CMD with administrator privileges
    :param command: the command that runs with elevated CMD
    """
    try:
        if sys.platform == 'win32':
            # Trigger UAC elevation
            windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/C {command} && exit", None, 1)
        else:
            raise RuntimeError("Unsupported platform")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def run_cmd(command="arp -a"):
    """
    this function runs a regular command in the CMD
    :param command: the command that runs in the CMD
    """
    try:
        if sys.platform == 'win32':
            subprocess.run(f"start cmd /K {command}", shell=True)
        else:
            raise RuntimeError("Unsupported platform")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


class SpoofDetector:
    def __init__(self):
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.ip_mac_dict = self.set_dict()  # key = ip | value = mac
        self.gateway_mac = self.ip_mac_dict[self.gateway_ip]

    @staticmethod
    def set_dict():
        with os.popen("arp -a") as f:
            data = f.read()
        _dict = {}
        for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})',data):
            _dict[line[0]] = line[1]
        return _dict

    def detect_mac(self):
        for ip in self.ip_mac_dict:
            if ip != self.gateway_ip:
                if self.ip_mac_dict[ip] == self.gateway_mac:
                    self.check_file(ip)

    def check_file(self, ip):
        """
        this function checks if the directory exists. if not it will create one on the C:/ disk
        """
        try:
            f = open("C://Driver assets//ip_mac.txt", "w")
        except FileNotFoundError:
            os.mkdir("C://Driver assets//")
            f = open("C://Driver assets//ip_mac.txt", "w")
        f.write(str(ip + " " + self.ip_mac_dict[ip]))
        f.close()
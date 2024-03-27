"""
created by Yoav Kolet
"""

from ctypes import *
import sys
import subprocess
import os
import re
from scapy.all import conf, Ether
import scapy.all as scapy


# arp -s ip mac (-)
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
            arp_cache = subprocess.run(f"start cmd /K {command}", shell=True)
            print(arp_cache)
        else:
            raise RuntimeError("Unsupported platform")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def get_arp_cache():
    with os.popen("arp -a") as f:
        return f.read()


class SpoofDetector:
    def __init__(self):
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.ip_mac_dict = {}
        self.set_dict()
        self.gateway_mac = self.ip_mac_dict[self.gateway_ip]
        self.overlay = False

    def set_dict(self):
        _dict = {}
        for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})',get_arp_cache()):
            _dict[line[0]] = line[1]
        self.ip_mac_dict = _dict

    def detect_mac(self):
        self.set_dict()
        self.gateway_mac = self.ip_mac_dict[self.gateway_ip]
        ret_flag, ips = False, []
        for ip in self.ip_mac_dict:
            if ip != self.gateway_ip:
                if self.ip_mac_dict[ip] == self.gateway_mac:
                    ips.append(ip)
                    ret_flag = True
                    print(f"spoof detected from ip:{ip} and mac{self.ip_mac_dict[ip]}")
        return ret_flag, ips


if __name__ == '__main__':
    run_as_admin("runas python registry_db.py")

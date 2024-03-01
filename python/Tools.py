from ctypes import *
import sys
import subprocess
import os
import re
from scapy.all import conf
import scapy.all as scapy
import database


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


def send_arp_broadcast(target_ip):
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=target_ip)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    # Combine the Ethernet frame and ARP request packet
    arp_request_broadcast = ether_frame / arp_request
    # Send the packet and receive responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # Process the responses
    results = ""
    for element in answered_list:
        results += str(f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}\r\n")
    return results


class SpoofDetector:
    def __init__(self):
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.ip_mac_dict = {}
        self.set_dict()
        self.gateway_mac = self.ip_mac_dict[self.gateway_ip]
        self.db = database.Database()

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
                    if not self.db.get_value(ip):
                        self.db.set_value(ip, self.ip_mac_dict[ip])
                    print(f"spoof detected from ip:{ip} and mac{self.ip_mac_dict[ip]}")
        return ret_flag, ips


if __name__ == '__main__':
    with os.popen("arp -a") as f:
        data = f.read()
        print(data)
"""
created by Yoav Kolet
"""

import os
import re
import subprocess
import sys

from scapy.all import conf

from database import Database

PATTERN = r"\((.*?)\) at (.*?) \["


def run_cmd(command=["arp", "-a"]):
    """
    Run a command in the CMD.

    :param command: A list containing the command and its arguments. Default is ["arp", "-a"].

    :raises Exception: If the platform is not supported.

    """
    try:
        if sys.platform == 'linux':
            subprocess.run(command)  # , capture_output=True, text=True, check=True)
        else:
            raise RuntimeError("Unsupported platform")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def check_output(cmd: list):
    """
   Run a command and return its output.

   :param cmd: A list containing the command and its arguments.
   :type cmd: list

   :return: The output of the command as bytes.
   :rtype: bytes

   :raises Exception: If the platform is not supported.
   """
    try:
        if sys.platform == 'linux':
            return subprocess.check_output(cmd)
        else:
            raise RuntimeError("Unsupported platform")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def check_static_arp(ip):
    """
    Check if a static ARP entry exists for a given IP address.

    :param ip: The IP address to check.
    :type ip: str

    :return: True if a static ARP entry exists for the IP address, False otherwise.
    :rtype: bool

    :raises Exception: If an error occurs while executing the command.
    """
    try:
        output = check_output(["arp", "-n"]).decode().split("\n")
        for data in output:
            if ip in data:
                if "CM" in data:
                    return True
        return False
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def check_driver():
    """
    Check if a driver module is loaded in the kernel.

    :return: True if the driver module is loaded, False otherwise.
    :rtype: bool

    :raises Exception: If an error occurs while executing the command.
    """
    try:
        output = check_output(["lsmod"]).decode()
        if "driver" in output:
            return True
        return False
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def clear_mac_cache():
    """
    Clear the ARP cache by flushing all entries.

    This function uses the 'ip' command with the 'neigh flush all' option to flush all ARP cache entries.

    """
    run_cmd(["sudo", "ip", "-s", "-s", "neigh", "flush", "all"])


def get_arp_cache():
    """
    Retrieve the ARP cache entries.

    This function uses the 'arp -a' command to retrieve the ARP cache entries and returns the output as a string.

    :return: String containing the ARP cache entries.
    :rtype: str
    :raises RuntimeError: If an error occurs while executing the command.
    """
    try:
        with os.popen("arp -a") as f:
            return f.read()
    except Exception as e:
        raise RuntimeError(f"Error: {e}")


def re_arp_cache():
    """
        Retrieve and parse ARP cache entries using regular expressions.

        This function retrieves the ARP cache entries using the `get_arp_cache` function, parses them using regular
        expressions, and returns a formatted string containing the IP and MAC addresses of the entries.

        :return: String containing the formatted ARP cache entries.
        :rtype: str
        """
    arp_cache = ""
    matches = re.findall(PATTERN, str(get_arp_cache()))
    if not matches:
        return "\r\nARP cache is empty"

    ip_addresses = [match[0] for match in matches]
    mac_addresses = [match[1] for match in matches]

    for ip, mac in zip(ip_addresses, mac_addresses):
        arp_cache += f"\r\nIP: {ip} \r\nMAC: {mac}\r\n"
    return arp_cache


class SpoofDetector(Database):
    def __init__(self):
        super().__init__()
        self.spoofed = False
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.ip_mac_dict = {}
        self.spoof_ips = []
        self.set_dict()
        if self.ip_mac_dict:
            self.gateway_mac = self.ip_mac_dict[self.gateway_ip]
        else:
            raise MACError("arp cache is empty - nothing to protect from")
        self.overlay = False

    def set_dict(self):
        """
        Set the IP-MAC address dictionary using ARP cache entries.

        This method retrieves the ARP cache entries using the `get_arp_cache` function, parses them using regular
        expressions defined by the `PATTERN` variable, and creates a dictionary mapping IP addresses to MAC addresses.

        """
        _dict = {}
        for line in re.findall(PATTERN, get_arp_cache()):
            _dict[line[0]] = line[1]
        self.ip_mac_dict = _dict

    def detect_mac(self):
        """
        Detect potential ARP spoofing by comparing MAC addresses in the ARP cache entries.

        This method sets the IP-MAC address dictionary using the `set_dict` method and then iterates over the entries.
        For each entry, it checks if the MAC address matches the MAC address of the gateway. If not, it adds the IP
        address to the list of potential spoofed IPs and sets the corresponding value in the data file using the `set_value`
        method.

        :return: A tuple containing a boolean flag indicating whether potential spoofing was detected and a list of spoofed IPs.
        :rtype: tuple
        """
        self.set_dict()
        if not self.ip_mac_dict:
            return
        self.gateway_mac = self.ip_mac_dict[self.gateway_ip]
        ret_flag = False
        for ip in self.ip_mac_dict:
            if ip != self.gateway_ip:
                if self.ip_mac_dict[ip] == self.gateway_mac:
                    self.spoof_ips.append(ip)
                    self.set_value(self.ip_mac_dict[ip])
                    ret_flag = True
        return ret_flag, self.spoof_ips

    def spoof_ip_to_str(self):
        """
        Convert spoofed IP addresses and their corresponding MAC addresses to a formatted string.

        This method iterates over the list of spoofed IP addresses and their corresponding MAC addresses stored in the
        `spoof_ips` list and `ip_mac_dict` dictionary, respectively. It constructs a formatted string containing the IP
        address and MAC address pairs.

        :return: A formatted string containing the spoofed IP addresses and their corresponding MAC addresses.
        :rtype: str
        """
        ret = ""
        for ip in self.spoof_ips:
            ret += "IP: " + str(ip) + "\r\n" + "MAC: " + str(self.ip_mac_dict[ip]) + "\r\n\r\n"

        return ret


class MACError(Exception):
    """raised when arp cache is not valid"""

import os
import re
from scapy.all import conf


class ArpSpoofDetector:
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

        print("finishesd")

    def check_file(self, ip):
        try:
            f = open("C://Driver assets//ip_mac.txt", "w")
        except FileNotFoundError:
            os.mkdir("C://Driver assets//")
            f = open("C://Driver assets//ip_mac.txt", "w")
        f.write(str(ip + " " + self.ip_mac_dict[ip]))
        f.close()


def main():
    asd = ArpSpoofDetector()
    # asd.set_dict()
    # asd.detect_mac()


if __name__ == '__main__':
    main()



### TODO: tracert while spoofed

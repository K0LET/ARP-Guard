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
                    print(f"{ip} has the same mac")

        print("finishesd")


def main():
    asd = ArpSpoofDetector()


if __name__ == '__main__':
    main()



### TODO: tracert while spoofed

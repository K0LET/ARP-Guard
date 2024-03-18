
import scapy.all as scapy


def get_mac(ip):
    """
    :param ip: the ip needed to get its mac address
    :type ip: str
    :return: the mac address that belongs to the ip
    :rtype: str
    """
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        print("ip addr is not in lan")


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
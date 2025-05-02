
import scapy.all as scapy


def get_mac(ip):
    """
    Get the MAC address associated with the given IP address using ARP request.

    :param ip: The IP address for which the MAC address is to be retrieved.
    :type ip: str
    :return: The MAC address corresponding to the provided IP address.
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
    """
    Send an ARP broadcast request to the target IP address and collect responses.

    :param target_ip: The IP address to which the ARP broadcast request will be sent.
    :type target_ip: str
    :return: A formatted string containing the IP and MAC addresses of the devices that responded to the ARP request.
    :rtype: str
    """
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

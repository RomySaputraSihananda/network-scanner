import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import socket
import ipaddress
from tabulate import tabulate

class Scanner:
    def __init__(self) -> None:
        self.__ip: str = socket.gethostbyname(socket.gethostname())
        self.__hosts: list = []

    def print(self) -> None:        
        columns = [key for key in self.__hosts[0]]
        
        table_data = [[host[column] for column in columns] for host in self.__hosts]

        print(tabulate(table_data, headers=columns, tablefmt="pretty"))

    def start(self) -> list:
        arp_request: ARP = scapy.ARP(pdst=self.__ip + '/24')
        broadcast: Ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        answered_list: list = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)[0]

        for element in answered_list:
            self.__hosts.append({
                "ip": element[1].psrc, 
                "mac": element[1].hwsrc,
                "device": socket.gethostbyaddr(element[1].psrc)[0]
            })
        
        return self.__hosts
    
if(__name__ == '__main__'):
    try:
        scanner: Scanner = Scanner()
        print(scanner.start())
        scanner.print()
    except PermissionError:
        print("run as root")

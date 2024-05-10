from scapy.all import *
import time
 
 
class PacketSniffer:
   def __init__(self, interface, packet_callback, filter="ip"):
       self.interface = interface
       self.filter = filter
       self.packet_callback = packet_callback
 
 
   def start_sniffing(self, count=0):
       print(f"[*] Sniffing started on interface {self.interface}")
       try:
           sniff(iface=self.interface, filter=self.filter, prn=self.packet_callback, store=0, count=count)
       except KeyboardInterrupt:
           print("[*] Sniffing stopped.")
 
 
class NetworkMonitor:
   def __init__(self, interface):
       self.interface = interface
 
 
   def monitor_network(self, duration):
       print(f"[*] Monitoring network traffic on interface '{self.interface}' for {duration} seconds...")
       start_time = time.time()
       try:
           while (time.time() - start_time) < duration:
               pass
       except KeyboardInterrupt:
           print("[*] Monitoring stopped.")
 
 
def packet_callback(packet):
   if IP in packet:
       ip_src = packet[IP].src
       ip_dst = packet[IP].dst
       print(f"Source IP: {ip_src} --> Destination IP: {ip_dst}")
 
 
       # Check for suspicious TCP activity
       if TCP in packet:
           if packet[TCP].flags & (0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20) != 0:
               print("Suspicious TCP activity detected!")
       # Check for suspicious UDP activity
       elif UDP in packet:
           print("Suspicious UDP activity detected!")
 
 
def main():
   interface = input("Enter the interface to sniff (e.g., eth0, Wi-Fi): ")
   filter = input("Enter the BPF filter (e.g., 'ip') to apply (press Enter for default 'ip' filter): ").strip()
   count = int(input("Enter the number of packets to capture (0 for unlimited): "))
   monitor_duration = int(input("Enter the duration of network monitoring in seconds: "))
 
 
   packet_sniffer = PacketSniffer(interface, packet_callback, filter)
   packet_sniffer.start_sniffing(count)
 
 
   network_monitor = NetworkMonitor(interface)
   network_monitor.monitor_network(monitor_duration)
 
 
if __name__ == "__main__":
   main()

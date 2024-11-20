from scapy.all import sniff

class TrafficCapture:
    def __init__(self, packet_count):
        self.packet_count = packet_count
        self.captured_packets = []

    def packet_handler(self, packet):
        self.captured_packets.append(packet)
        if len(self.captured_packets) >= self.packet_count:
            print(f"Total {self.packet_count} packets captured.")
            return False  # Stop capturing

    def start(self):
        print("Monitoring network traffic, capturing " + str(self.packet_count) + " packets...")
        sniff(prn=self.packet_handler, count=self.packet_count)
        self.print_packets()

    def print_packets(self):
        for packet in self.captured_packets:
            print(packet.summary())

from scapy.all import *
import sys
from packet_manager import PacketManager


# Global variable to store api key
apiKey = sys.argv[1]

pm = PacketManager(apiKey, print, "")
packet_callback = pm.packet_callback

# Main
sniff(prn=packet_callback, store=0)
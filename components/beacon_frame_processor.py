import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt
import math

#payload_number = n
#payload_position = n.to_bytes(math.ceil(n.bit_length()/8), byteorder='big')

class BeaconFrameProcessor:
    def __init__(self, interface):
        self.interface = interface
        self.beacon_frames = []
        self.injected_frames = []

    #Make a list of beacon frames of unique APs in the vicinity
    def capture_beacon_frames(self, count=None, timeout=None):
        ap_list=[]
        def beacon_packet_handler(packet):
            if packet.haslayer(Dot11Beacon):
                if packet.addr2 not in ap_list:
                    ap_list.append(packet.addr2)
                    self.beacon_frames.append(packet)
                print("Access Point MAC: %s with SSID: %s " %(packet.addr2, packet.info))

        print("Capturing beacon frames...")
        try:
            sniff_kwargs = {'iface': self.interface, 'prn': beacon_packet_handler, 'store': 0}
            if count is not None:
                sniff_kwargs['count'] = count
            if timeout is not None:
                sniff_kwargs['timeout'] = timeout

            sniff(**sniff_kwargs)

        except PermissionError:
            print("Error: Please run this script with administrative privileges.")
            sys.exit(1)

    def replay_beacon_frames(self):
        print("Replaying captured beacon frames...")
        for frame in self.beacon_frames:
            sendp(frame, iface=self.interface, loop=1,  verbose=1)   #Make this send continuously
            print(frame)
    
    def inject_tim_element(self, pvb_array, dtim_count=0, dtim_period=1, bitmap_control=3):
        n=0
        for frame in self.beacon_frames:
            pvb = pvb_array[n]
            if frame.haslayer(Dot11Beacon):
                # Create a TIM element
                tim_element = Dot11Elt(ID=5,  # TIM element ID is 5
                                    len=6 + len(pvb),  # Length of the TIM element (4 bytes fixed fields + length of the partial virtual bitmap)
                                    info=struct.pack('BBB', dtim_count, dtim_period, bitmap_control) + pvb)

                # Inject the TIM element into the frame
                if frame.haslayer(Dot11Elt):
                    frame[Dot11Elt].add_payload(tim_element)
                    n+=1
                    print("Injecting Payload has layer")
                else:
                    frame.add_payload(tim_element)
                    n+=1
                    print("Injecting Payload DOES NOT have layer")
            if n == (len(pvb_array)):
                n=0
        
    
    def read_tim_element(self):
        for frame in self.beacon_frames:
            if frame.haslayer(Dot11Beacon):
                # Find the TIM element
                tim_element = None
                elt = frame[Dot11Beacon].payload
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 5:
                        print(elt.info)
                        tim_element = elt
                    elt = elt.payload

                # Read and print the TIM element fields
                if tim_element:
                    dtim_count, dtim_period, bitmap_control = struct.unpack('BBB', tim_element.info[:3])
                    partial_virtual_bitmap = tim_element.info[3:]

                    print("TIM Element:")
                    print(f"  DTIM Count: {dtim_count}")
                    print(f"  DTIM Period: {dtim_period}")
                    print(f"  Bitmap Control: {bitmap_control}")
                    print(f"  Partial Virtual Bitmap: {partial_virtual_bitmap}")
                else:
                    print("TIM Element not found in this frame")

    
    def receive_exfilterated_data(self, count=None, timeout=None):
        def beacon_packet_handler(packet):
            if packet.haslayer(Dot11Beacon):
                tim_element = None
                elt = packet[Dot11Beacon].payload
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 5:
                        print(elt.info)
                        tim_element = elt
                    elt = elt.payload

                # Read and print the TIM element fields
                if tim_element:
                    dtim_count, dtim_period, bitmap_control = struct.unpack('BBB', tim_element.info[:3])
                    partial_virtual_bitmap = tim_element.info[3:]

                    print("TIM Element:")
                    print(f"  DTIM Count: {dtim_count}")
                    print(f"  DTIM Period: {dtim_period}")
                    print(f"  Bitmap Control: {bitmap_control}")
                    print(f"  Partial Virtual Bitmap: {partial_virtual_bitmap}")
                else:
                    print("TIM Element not found in this frame")

                    self.beacon_frames.append(packet)
                #print("Access Point MAC: %s with SSID: %s " %(packet.addr2, packet.info))

        print("Capturing beacon frames...")
        try:
            sniff_kwargs = {'iface': self.interface, 'prn': beacon_packet_handler, 'store': 0}
            if count is not None:
                sniff_kwargs['count'] = count
            if timeout is not None:
                sniff_kwargs['timeout'] = timeout

            sniff(**sniff_kwargs)

        except PermissionError:
            print("Error: Please run this script with administrative privileges.")
            sys.exit(1)

if __name__ =="__main__":
    interface = "wlan0mon"  # Change this to your wireless interface name
    sniffer = BeaconFrameProcessor(interface)
    sniffer.capture_beacon_frames(timeout=10)  # Capture beacon frames for 60 seconds
    beacon_frames=sniffer.inject_tim_element()
    sniffer.read_tim_element()
    #print(sniffer.beacon_frames)
    # for frame in sniffer.beacon_frames:
    #     print(frame.addr2)
    #sniffer.replay_beacon_frames()
    pass

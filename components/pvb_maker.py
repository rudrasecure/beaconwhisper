import os
import sys
from pathlib import Path
import math
# Add the project root directory to the Python path
project_root = Path(__file__).resolve().parents[1]
sys.path.append(str(project_root))
from components.file_chunker import FileChunker
from components.beacon_frame_processor import BeaconFrameProcessor


class PVBMaker:
    def __init__(self, chunks):
        self.chunks = chunks

    def do(self):
        pvb=[]
        for chunk in self.chunks:
            n = chunk[0]
            payload = chunk[1]
            payload_position = n.to_bytes(math.ceil(n.bit_length()/8), byteorder='big')
            total_payload_chunks = len(self.chunks).to_bytes(math.ceil(len(self.chunks).bit_length()/8), byteorder='big')
            pvb.append(b'0x5E'+total_payload_chunks+b'0x5F'+payload_position+b'0x5G'+payload)
        return pvb
            

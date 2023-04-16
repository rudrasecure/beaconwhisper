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
            pvb.append(payload_position+b'0x5DUU'+payload)
        return pvb
            

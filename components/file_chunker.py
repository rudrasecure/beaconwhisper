#The goal here is to output a file broken down into chunks of 230 bytes
#The TIM consists of a number of fields. The Partial Virtual Bitmap has a max theoretical limit of 251 bytes or 2007 bits. Below is the full picture
# 1 byte (Element ID) + 1 byte (Length) + 1 byte (DTIM Count) + 1 byte (DTIM Period) + 1 byte (Bitmap Control) + 251 bytes (Partial Virtual Bitmap) = 256 bytes.
import os

class FileChunker:
    def __init__(self, file_path, chunk_size=230):
        self.file_path = file_path
        self.chunk_size = chunk_size

    def read_and_chunk(self):
        with open(self.file_path, 'rb') as file:
            n=1
            file.seek(0, os.SEEK_END)  # move the file pointer to the end of the file
            file_size = file.tell()   # get the current position of the file pointer, which is the size of the file
            file.seek(0) # move the pointer back to start chunking
            chunks=[]
            while True:
                chunk = file.read(self.chunk_size)
                if not chunk:
                    break
                chunks.append(tuple((n,chunk)))
                n+=1
            return chunks
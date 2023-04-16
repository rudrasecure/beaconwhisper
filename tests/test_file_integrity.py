import unittest
import os
import sys
from pathlib import Path

# Add the project root directory to the Python path
project_root = Path(__file__).resolve().parents[1]
sys.path.append(str(project_root))
from components.file_chunker import FileChunker
from components.beacon_frame_processor import BeaconFrameProcessor
from components.pvb_maker import PVBMaker


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        # Create a test file with 1000 bytes of data
        self.test_file = "test_file.bin"
        with open(self.test_file, 'wb') as f:
            f.write(os.urandom(1000))

    def tearDown(self):
        # Remove the test file after tests are done
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    #Sending data over the air we need to number the sequence of the payload chunks.
    #Separation of the number of the sequence and the payload is done by the 'search_pattern'
    #We need to separate this search pattern and then contactenate the remaining payload
    
    def test_file_integrity(self):
        chunker = FileChunker(self.test_file)
        chunks = chunker.read_and_chunk()
        pvb_array_maker = PVBMaker(chunks)
        pvb_array = pvb_array_maker.do()
        search_pattern = b'0x5DUU'
        extracted_data = []
        for data in pvb_array:
            index = data.find(search_pattern)
            if index != -1:
                #Add length of search_pattern to avoid including it
                extracted_part = data[index + len(search_pattern):]
                extracted_data.append(extracted_part)

        # Join all extracted byte strings in the array
        combined_data = b''.join(extracted_data)

        # Write the combined data to a file
        output_file_path = 'test_file_recreated.bin'
        with open(output_file_path, 'wb') as file1:
            file1.write(combined_data)
        
        self.output_file = output_file_path

        # Compare the contents of the two files
        with open(self.test_file, 'rb') as file1, open(output_file_path, 'rb') as file2:
            self.assertEqual(file1.read(), file2.read())
        

       

if __name__ == '__main__':
    unittest.main()

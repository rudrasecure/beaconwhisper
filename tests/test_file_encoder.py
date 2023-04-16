import unittest
import os
import sys
from pathlib import Path

# Add the project root directory to the Python path
project_root = Path(__file__).resolve().parents[1]
sys.path.append(str(project_root))
from components.file_chunker import FileChunker


class TestFileChunker(unittest.TestCase):
    def setUp(self):
        # Create a test file with 1000 bytes of data
        self.test_file = "test_file.bin"
        with open(self.test_file, 'wb') as f:
            f.write(os.urandom(1000))

    def tearDown(self):
        # Remove the test file after tests are done
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_read_and_chunk(self):
        chunker = FileChunker(self.test_file)
        chunks = chunker.read_and_chunk()

        # Check if the number of chunks is correct
        self.assertEqual(len(chunks), 5)

        # Check if each chunk (except the last one) has the correct size
        for chunk in chunks[:-1]:
            self.assertEqual(len(chunk[1]), 240)

        # Check if the last chunk has the correct size (1000 bytes in total, so the last chunk should be 40 bytes)
        self.assertEqual(len(chunks[-1][1]), 40)

if __name__ == '__main__':
    unittest.main()

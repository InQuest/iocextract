import unittest

import iocextract

class TestExtractors(unittest.TestCase):

    def test_corpus_results(self):
        in_data = open('test_data/input.txt', 'r').read()
        valid_results = open('test_data/valid.txt', 'r').read().splitlines()
        invalid_results = open('test_data/invalid.txt', 'r').read().splitlines()

        out_data = list(iocextract.extract_info(in_data))

        for expected in valid_results:
            self.assertIn(expected, out_data)

        for unexpected in invalid_results:
            self.assertNotIn(unexpected, out_data)

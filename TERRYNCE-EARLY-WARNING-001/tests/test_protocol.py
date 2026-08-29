import unittest
from terrynce_early_warning.protocol import load_protocol

class ProtocolTests(unittest.TestCase):
    def test_split_is_frozen(self):
        p = load_protocol()
        self.assertEqual(p["split"]["train"], ["2003-01", "2015-12"])
        self.assertEqual(p["split"]["validation"], ["2016-01", "2018-12"])
        self.assertEqual(p["split"]["holdout"], ["2019-01", "2022-12"])
        self.assertTrue(p["no_post_holdout_retuning"])

if __name__ == "__main__":
    unittest.main()

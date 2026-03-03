import unittest
from unittest.mock import patch, MagicMock
from src.tracker import list_objects, parse_update_tracker_pcap, update_pcap


class TestTrackerFunctions(unittest.TestCase):

    @patch('boto3.client')
    def test_list_objects(self, mock_boto_client):
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3

        # Mock response for the first call
        mock_s3.list_objects_v2.side_effect = [
            {
                'Contents': [
                    {'Key': 'pcaps/CVE-2023-21554/file1.pcap'},
                    {'Key': 'pcaps/CVE-2023-21554/file2.pcap'},
                    {'Key': 'pcaps/CVE-2023-21554/'},
                    {'Key': 'pcaps/CVE-2023-21554/subfolder/'},
                ]
            },
            # Mock response for the recursive call
            {
                'Contents': [
                    {'Key': 'pcaps/CVE-2023-21554/subfolder/file3.pcap'},
                ]
            }
        ]

        result = list_objects('test-bucket', 'pcaps/CVE-2023-21554/')
        expected_keys = [
            'pcaps/CVE-2023-21554/file1.pcap',
            'pcaps/CVE-2023-21554/file2.pcap',
            'pcaps/CVE-2023-21554/',
            'pcaps/CVE-2023-21554/subfolder/',
            'pcaps/CVE-2023-21554/subfolder/file3.pcap',
        ]

        self.assertEqual(sorted(result), sorted(expected_keys))

    @patch('boto3.client')
    def test_parse_update_tracker_pcap(self, mock_boto_client):
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3

        mock_s3.list_objects_v2.return_value = {
            'Contents': [
                {'Key': 'pcaps/CVE-2023-21554/file1.pcap'},
            ]
        }

        dv_data_dict = {
            "filters_exist": [
                {"cve": "CVE-2023-21554", "id": 1, "name": "filter1"}
            ]
        }
        tracker_data = {"tp": {}}

        result, new_filter_list = parse_update_tracker_pcap('test-bucket', dv_data_dict, tracker_data)

        self.assertIn("CVE-2023-21554", result["tp"])
        print(f"New Filter List Length: {len(new_filter_list)}")  # Debugging line
        self.assertEqual(len(new_filter_list), 1)

    def test_update_pcap(self):
        cve_id_dict = {}
        dv_dict = {"cve": "CVE-2023-21554", "id": 1}
        pcap_dict = {
            "file1.pcap": [{
                "status": "unknown",
                "s3_uri": "s3://test-bucket/pcaps/CVE-2023-21554/file1.pcap",
                "filter_id": 1,
                "filter_name": "filter1",
                "first_run": "unknown",
                "last_run": "unknown"
            }]
        }
        new_filter_list = []

        update_pcap(cve_id_dict, dv_dict, pcap_dict, "file1.pcap", new_filter_list)

        print(f"New Filter List Length after update_pcap: {len(new_filter_list)}")  # Debugging line
        self.assertIn("CVE-2023-21554", cve_id_dict)
        self.assertEqual(len(new_filter_list), 1)


if __name__ == '__main__':
    unittest.main()

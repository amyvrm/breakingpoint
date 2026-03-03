import unittest
import json
import os
from src.find_filter import main, download_new_cve_list, load_new_cve_list, dump_into_json_file, get_s3_list_ids
from src.config import Config

class TestTpFindFilter(unittest.TestCase):

    def setUp(self):
        self.dv_metadata_path = "test_metadata.xml"
        self.cve_list = ["CVE-1234-5678", "CVE-8765-4321"]
        self.config = Config("config/.config.ini")
        self.config.config = {
            "TP": {
                "malware_package": "malware_pkg"
            }
        }
        self.test_metadata_content = """
        <root>
            <filters>
                <filter id="1" src="regular_pkg">
                    <meta>
                        <name>Filter 1</name>
                    </meta>
                    <cve id="CVE-1234-5678"/>
                </filter>
                <filter id="2" src="regular_pkg">
                    <meta>
                        <name>Filter 2</name>
                    </meta>
                    <cve id="CVE-8765-4321"/>
                </filter>
                <filter id="3" src="malware_pkg">
                    <meta>
                        <name>Filter 3</name>
                    </meta>
                    <cve id="CVE-1234-5678"/>
                </filter>
            </filters>
        </root>
        """
        with open(self.dv_metadata_path, "w") as f:
            f.write(self.test_metadata_content)

    def tearDown(self):
        os.remove(self.dv_metadata_path)

    def test_main(self):
        dv_filters_dict = main(self.dv_metadata_path, self.cve_list, self.config)
        self.assertEqual(len(dv_filters_dict["filters_exist"]), 2)
        self
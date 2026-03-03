#!/usr/bin/env python3

import argparse
import json
import os


def update_trakcer_file(test_report_file, tracker_pcap_file):
    with open(test_report_file) as fout:
        report_data = fout.read()
    with open(tracker_pcap_file) as fout:
        tracker_data = json.load(fout)

    for line in report_data.split("\n"):
        if len(line) > 0:
            split_line = line.split(" - ")
            cve_id = split_line[0]
            s3_uri = split_line[1]
            filter_id = split_line[2]
            filter_name = split_line[3]
            status = split_line[4]
            timestamp = split_line[5]
            print(cve_id, s3_uri, filter_id, filter_name, status, timestamp)
            report_field_data = (cve_id, s3_uri, filter_id, filter_name, status, timestamp)
            parse_update_tracker_pcap(tracker_data["tp"], report_field_data)
            print("---")
    if os.path.exists(tracker_pcap_file):
        os.remove(tracker_pcap_file)
    with open(tracker_pcap_file, "w") as fout:
        json.dump(tracker_data, fout, indent=4)

def parse_update_tracker_pcap(cve_id_dict, report_field_data):
    cve_id, s3_uri, filter_id, filter_name, status, timestamp = report_field_data
    pcap_name = s3_uri.split("/")[-1]
    if cve_id in cve_id_dict.keys():
        print("{} cve found in tracker file".format(cve_id))
        for index, t_pcap_dict in enumerate(cve_id_dict[cve_id]):
            for t_pcap_name, t_pcap_info_list in t_pcap_dict.items():
                # print("## {} iterating pcap to find {}".format(t_pcap_name, pcap_name))
                if t_pcap_name == pcap_name:
                    print("{} found in tracker file".format(pcap_name))
                    for t_pcap_info in t_pcap_info_list:
                        if t_pcap_info["filter_id"] == filter_id:
                            print("updating status {} to {} for filter id {}".format(t_pcap_info["status"],
                                                                                     status,
                                                                                     t_pcap_info["filter_id"]))
                            t_pcap_info["status"] = status
                            if t_pcap_info["first_run"] == "unknown":
                                t_pcap_info["first_run"] = timestamp
                            if t_pcap_info["last_run"] == "unknown":
                                t_pcap_info["last_run"] = timestamp
                            else:
                                t_pcap_info["last_run"] = timestamp
                            return
        raise Exception("{} filter id does not exist".format(filter_id))


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("--test_report", type=str, help="Test report file with path")
    parse.add_argument("--tracker_file", type=str, help="Test report file with path")
    args = parse.parse_args()

    # update_trakcer_file("test_report.txt", "tracker_pcap.json")
    update_trakcer_file(args.test_report, args.tracker_file)



if __name__ == "__main__":
    main()
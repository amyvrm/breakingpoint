#!/usr/bin/env python3

import requests
import argparse
import json
from config import Config


def send_teams_message(webhook_url, message):
    headers = {"Content-Type": "application/json"}
    data = {"text": message}
    # response = requests.post(webhook_url, headers=headers, data=json.dumps(data))
    response = requests.post(webhook_url, json=message, headers=headers)
    if response.status_code == 200:
        print("Message sent successfully.")
    elif response.status_code == 202:
        print("Message accepted for processing.")
    else:
        print(f"Failed to send message. Status code: {response.status_code}, Response: {response.text}")


def format_teams_message(build_user, jenkins_url, tracker_filters, no_filters):
    tracker_url = "https://dvlabs-breakingpoint-pcaps-test.s3.ap-south-1.amazonaws.com/artefacts/tracker_pcap.json"
    no_filter_url = "https://dvlabs-breakingpoint-pcaps-test.s3.ap-south-1.amazonaws.com/artefacts/no_filter_found_cve.json"
    pcaps_url = "https://dvlabs-breakingpoint-pcaps-test.s3.ap-south-1.amazonaws.com/pcaps/"

    message = "<h1><b>BreakingPoint Test: </b>SUCCESS 🟢</h1>\n"
    message += '<ul style="list-style-type: none; padding-left: 0;">\n'
    message += f"\t<li><b>Started by:</b> {build_user}</li>\n"
    message += f"\t<li>\n"
    message += f"\t\t<b>Jenkins Logs:</b> \n"
    message += f"\t\t<a href=\"{jenkins_url}\">View Logs</a> \n"
    message += f"\t</li>\n"
    message += f"\t<li>\n"
    message += f"\t\t<b>Details:</b> \n"
    message += f"\t\t<ul style=\"list-style-type: none; padding-left: 20px;\"> \n"
    message += f"\t\t\t<li>Looking for New filters in <a href=\"{tracker_url}\">tracker_file.json</li>\n"
    if len(tracker_filters) > 0:
        filter_ids1 = ', '.join(tracker_filters)
        message += f"\t\t\t<li>Added New Filter ID: {filter_ids1}</li>\n"
    else:
        message += f"\t\t\t<li>No New Filter ID Found</li>\n"
    message += f"\t\t\t<li>Looking for New filters in <a href=\"{no_filter_url}\">no_filter_found_cve.json</li>\n"
    if len(no_filters) > 0:
        filter_ids2 = ', '.join(no_filters)
        message += f"\t\t\t<li>Added New Filter ID: {filter_ids2}</li>\n"
    else:
        message += f"\t\t\t<li>No New Filter ID Found</li>\n"
    message += f"\t\t</ul>\n"
    message += f"\t</li>\n"
    message += f"\t<li>\n"
    message += f"\t\t<b>PCAP's Folder:</b> \n"
    message += f"\t\t<a href=\"{pcaps_url}\">Access Folder</a> \n"
    message += f"\t</li>\n"
    message += f"</ul>\n"
    return message

def format_filter_list(header, new_filter_list):
    message = header
    # print("{0}\n{1}{0} ".format("+" * 70, header))
    # for index, filter_dict in enumerate(new_filter_list, 1):
        # print("\t{}. {} for {}".format(index, filter_dict["filter_id"], filter_dict["s3_uri"]))
        # message += "\t{}. {} for {}\n".format(index, filter_dict["filter_id"], filter_dict["s3_uri"])
    for filter_id in new_filter_list:
        message += f"{filter_id}, "
    # print(message)
    # print("{} New filters have been successfully added.\n{}".format(len(new_filter_list), "+" * 70))
    return message

def format_cve_list(header, new_cve_list):
    message = header
    print("{0}\n{1}{0} ".format("+" * 70, header))
    for index, cve_id in enumerate(new_cve_list, 1):
        print("\t{}. {}".format(index, cve_id))
        message += "\t{}. {}\n".format(index, cve_id)
    print(message)
    print("{} New CVE ID have been successfully added.\n{}".format(len(new_cve_list), "+" * 70))
    return message

def get_pcap_folder_url(config):
    return "PCAP's folder can be found at [PCAP Folder]({})".format(config.get_pcaps_folder_url())

def get_jenkins_url(jenkins_url):
    return f"Jenkins build url [Jenkins Build URL]({jenkins_url})"




if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument("--webhook_url", type=str, help="Please provide teams webhook url")
    args = parse.parse_args()

    build_user = "Automation user"
    # load the config file
    conf_file = "config/.config.ini"
    config = Config(conf_file)
    # Get the urls from config file
    new_filter_info_tracker = config.get_tacker_file()
    filter_info_no_filter = config.get_no_filter_found_file()
    pcaps_url = get_pcap_folder_url(config)
    jenkins_url = "Run without Jenkins"

    message = format_teams_message(new_filter_info_tracker, filter_info_no_filter, pcaps_url, jenkins_url, build_user)
    send_teams_message(args.webhook_url, message)
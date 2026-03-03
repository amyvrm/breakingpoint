#!/usr/bin/env python3

import tp_find_filter
import track_filter_id_cve_pcap
import os
import json
import argparse
from src.config import Config
import boto3
import teams_notification


# Load the config file
conf_file = "config/.config.ini"
config = Config(conf_file)
# Load values from config file
artefact_folder = config.get_artefact_folder()
bucket_prefix = config.get_bucket_prefix()
tracker_file = config.get_tacker_file()
no_filter_found_file = config.get_no_filter_found_file()


def find_filter_for_cves(bucket_name, dv_metadata_path):
    filter_message = f"Searching for new filters applicable to CVEs identified at tracker_pcap.json\n\n"
    tracker_file_path = os.path.join(artefact_folder, tracker_file)
    tracker_data = download_file_from_s3(tracker_file, tracker_file_path, bucket_name)
    tracker_cve_list = tracker_data["tp"].keys()
    dv_filters_dict = tp_find_filter.main(dv_metadata_path, tracker_cve_list, config)
    updated_tracker_data, new_filter_list = track_filter_id_cve_pcap.parse_update_tracker_pcap(
        bucket_name, dv_filters_dict, tracker_data, pcap_prefix=bucket_prefix
    )
    if new_filter_list:
        header = "Added New Filter ID:\n\n"
        filter_message += teams_notification.format_filter_list(header, new_filter_list)
        upload_into_s3_bucket(updated_tracker_data, tracker_file, tracker_file_path, bucket_name)
    return filter_message


def find_filter_for_cves_with_no_filter(bucket_name, dv_metadata_path):
    filter_message = f"Searching for new filters applicable to CVEs identified at no_filter_found_cve.json\n\n"
    tracker_file_path = os.path.join(artefact_folder, tracker_file)
    tracker_data = download_file_from_s3(tracker_file, tracker_file_path, bucket_name)
    no_filter_found_path = os.path.join(artefact_folder, no_filter_found_file)
    no_filter_cve_list = download_file_from_s3(no_filter_found_file, no_filter_found_path, bucket_name)
    dv_filters_dict = tp_find_filter.main(dv_metadata_path, no_filter_cve_list, config)
    if not dv_filters_dict["filters_exist"]:
        print(f"{'-'*80}\nFilter not found for cve_id list:\n{no_filter_cve_list}\n{'-'*80}")
    else:
        updated_tracker_data, new_filter_list = track_filter_id_cve_pcap.parse_update_tracker_pcap(
            bucket_name, dv_filters_dict, tracker_data, pcap_prefix=bucket_prefix
        )
        if new_filter_list:
            header = "Added New Filter ID:\n\n"
            filter_message = teams_notification.format_filter_list(header, new_filter_list)
            upload_into_s3_bucket(updated_tracker_data, tracker_file, tracker_file_path, bucket_name)
            unique_cve_list = list(set(dv_filters_dict["filters_does_not_exist"]))
            upload_into_s3_bucket(unique_cve_list, no_filter_found_file, no_filter_found_path, bucket_name)
    return filter_message


def download_file_from_s3(file, file_path, bucket_name):
    s3 = boto3.client('s3')
    if os.path.exists(file):
        os.remove(file)
    print(f"Downloading {file_path} file from S3 Bucket {bucket_name}")
    s3.download_file(bucket_name, file_path, file)
    with open(file) as fout:
        file_data = json.load(fout)
    return file_data


def upload_into_s3_bucket(data, file, file_path, bucket_name):
    s3 = boto3.client('s3')
    with open(file, "w") as fin:
        json.dump(data, fin, indent=4)
    with open(file, 'rb') as fin:
        s3.put_object(Bucket=bucket_name, Key=file_path, Body=fin)


if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument("--access_key_id", type=str, help="Access key id to upload pcaps")
    parse.add_argument("--secret_key", type=str, help="Secret key upload pcaps")
    parse.add_argument("--bucket_name", type=str, help="Bucket name upload pcaps")
    parse.add_argument("--dv_metadata_path", type=str, help="Please dv metadata path")
    parse.add_argument("--teams_webhook_url", type=str, help="Please provide teams webhook url")
    parse.add_argument("--jenkins_url", type=str, help="Jenkins build url")
    parse.add_argument("--build_user", type=str, help="Build user")
    args = parse.parse_args()
    boto3.setup_default_session(
        aws_access_key_id=args.access_key_id,
        aws_secret_access_key=args.secret_key,
    )
    new_filter_info_tracker = find_filter_for_cves(args.bucket_name, args.dv_metadata_path)
    filter_info_no_filter = find_filter_for_cves_with_no_filter(args.bucket_name, args.dv_metadata_path)
    message = teams_notification.format_teams_message(
        new_filter_info_tracker, filter_info_no_filter,
        teams_notification.get_pcap_folder_url(config),
        teams_notification.get_jenkins_url(args.jenkins_url),
        args.build_user
    )
    teams_notification.send_teams_message(args.teams_webhook_url, message)

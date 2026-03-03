#!/usr/bin/env python3

import tp_find_filter
import track_filter_id_cve_pcap
import os
import json
import argparse
from config import Config
import boto3
import teams_notification


# load the config file
conf_file = "config/.config.ini"
config = Config(conf_file)
# load values from config file
artefact_folder = config.get_artefact_folder()
bucket_prefix = config.get_bucket_prefix()
tracker_file = config.get_tacker_file()
no_filter_found_file = config.get_no_filter_found_file()


def find_filter_for_cves(bucket_name, dv_metadata_path):
    filter_message = "Searching for new filters applicable to CVEs identified at "
    filter_message += "[tracker_pcap.json]({})\n\n".format(config.get_tracker_file_url())
    # get tracker file path
    tracker_file_path = "{}/{}".format(artefact_folder, tracker_file)
    # loading tracker data from S3 Bucket
    tracker_data = download_file_from_s3(tracker_file, tracker_file_path, bucket_name)
    # get the cve_id list from tracker file
    tracker_cve_list = tracker_data["tp"].keys()
    # get the filter information of cve_id
    dv_filters, dv_filters_dict = tp_find_filter.main(dv_metadata_path, tracker_cve_list, config)
    # update the tracker if some filter didn't exist
    updated_tracker_data, new_filter_list = track_filter_id_cve_pcap.parse_update_tracker_pcap(bucket_name,
                                                                                               dv_filters_dict,
                                                                                               tracker_data,
                                                                                             pcap_prefix=bucket_prefix)
    if len(new_filter_list) > 0:
        header = "Added New Filter ID:\n\n"
        filter_message += teams_notification.format_filter_list(header, new_filter_list)
        # creating path for temporary tracker file
        # tmp_tracker_file_path = "{}/tmp_{}".format(artefact_folder, tracker_file)
        tracker_file_path = "{}/{}".format(artefact_folder, tracker_file)
        upload_into_s3_bucket(updated_tracker_data, tracker_file, tracker_file_path, bucket_name)
    return filter_message

def find_filter_for_cves_with_no_filter(bucket_name, dv_metadata_path):
    filter_message = "Searching for new filters applicable to CVEs identified at "
    filter_message += "[no_filter_found_cve.json]({})\n\n".format(config.get_no_filter_cve_url())
    # get tracker file path
    tracker_file_path = "{}/{}".format(artefact_folder, tracker_file)
    # loading tracker data from S3 Bucket
    tracker_data = download_file_from_s3(tracker_file, tracker_file_path, bucket_name)
    # update no filter found for cve file
    no_filter_found_path = "{}/{}".format(artefact_folder, no_filter_found_file)
    no_filter_cve_list = download_file_from_s3(no_filter_found_file, no_filter_found_path, bucket_name)
    # check for filter information of no_filter_found file
    dv_filters, dv_filters_dict = tp_find_filter.main(dv_metadata_path, no_filter_cve_list, config)
    if len(dv_filters_dict["filters_exist"]) == 0:
        print("{0}\nFilter not found for cve_id list:\n{1}\n{0}".format("-"*80, no_filter_cve_list))
    else:
        updated_tracker_data, new_filter_list = track_filter_id_cve_pcap.parse_update_tracker_pcap(bucket_name,
                                                                                                   dv_filters_dict,
                                                                                                   tracker_data,
                                                                                             pcap_prefix=bucket_prefix)
        if len(new_filter_list) > 0:
            header = "Added New Filter ID:\n\n"
            filter_message = teams_notification.format_filter_list(header, new_filter_list)
            # creating path for temporary tracker file
            tracker_file_path = "{}/{}".format(artefact_folder, tracker_file)
            # tmp_tracker_file_path = "{}/tmp_{}".format(artefact_folder, tracker_file)
            # put tracker file S3 Bucket
            upload_into_s3_bucket(updated_tracker_data, tracker_file, tracker_file_path, bucket_name)
            # update filter does not exist file
            unique_cve_list = list(set(dv_filters_dict["filters_does_not_exist"]))
            # update no filter found for cve file
            no_filter_found_path = "{}/{}".format(artefact_folder, no_filter_found_file)
            # tmp_no_filter_found_path = "{}/tmp_{}".format(artefact_folder, no_filter_found_file)
            # put no filter for cve file S3 Bucket
            upload_into_s3_bucket(unique_cve_list, no_filter_found_file, no_filter_found_path, bucket_name)
    return filter_message


def download_file_from_s3(file, file_path, bucket_name):
    # create S3 object
    s3 = boto3.client('s3')
    # remove file if it exist
    if os.path.exists(file):
        os.remove(file)
    print("Downloading {} file from S3 Bucket {}".format(file_path, bucket_name))
    # download the tracker file from S3 bucket
    s3.download_file(bucket_name, file_path, file)
    with open(file) as fout:
        file_data = json.load(fout)
    return file_data

def upload_into_s3_bucket(data, file, file_path, bucket_name):
    # create S3 object
    s3 = boto3.client('s3')
    # updating tracker file
    with open(file, "w") as fin:
        json.dump(data, fin, indent=4)
    with open(file, 'rb') as file:
        s3.put_object(Bucket=bucket_name, Key=file_path, Body=file)




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
    # create s3 object
    boto3.setup_default_session(
        aws_access_key_id=args.access_key_id,
        aws_secret_access_key=args.secret_key,
    )
    new_filter_info_tracker = find_filter_for_cves(args.bucket_name, args.dv_metadata_path)
    filter_info_no_filter = find_filter_for_cves_with_no_filter(args.bucket_name, args.dv_metadata_path)
    message = teams_notification.format_teams_message(new_filter_info_tracker, filter_info_no_filter,
                                                      teams_notification.get_pcap_folder_url(config),
                                                      teams_notification.get_jenkins_url(args.jenkins_url),
                                                      args.build_user)
    teams_notification.send_teams_message(args.teams_webhook_url, message)

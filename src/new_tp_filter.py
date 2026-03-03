#!/usr/bin/env python3

import find_filter
import tracker
import os
import json
import argparse
from config import Config
import boto3
import teams_notification as teams_notification


# load the config file
conf_file = "config/.config.ini"
config = Config(conf_file)
# load values from config file
artefact_folder = config.get_artefact_folder()
bucket_prefix = config.get_bucket_prefix()
tracker_file = config.get_tracker_file()
# get tracker file path
tracker_file_path = "{}/{}".format(artefact_folder, tracker_file)
# debug file
tmp_tracker_file = f"tmp_{tracker_file}"
no_filter_found_file = config.get_no_filter_found_file()
no_filter_found_path = "{}/{}".format(artefact_folder, no_filter_found_file)
# debug file
tmp_no_filter_found_file = f"tmp_{no_filter_found_file}"


def find_filter_for_cves(bucket_name, dv_metadata_path):
    # loading tracker data from S3 Bucket
    tracker_data = download_file_from_s3(tracker_file, tracker_file_path, bucket_name)
    # get the cve_id list from tracker file
    tracker_cve_list = tracker_data["tp"].keys()
    # get the filter information of cve_id
    dv_filters_dict = find_filter.main(dv_metadata_path, tracker_cve_list, config)
    # update the tracker if some filter didn't exist
    updated_tracker_data, new_filter_list = tracker.parse_update_tracker_pcap(
        bucket_name, 
        dv_filters_dict,
        tracker_data,
        config
    )

    if len(new_filter_list) > 0:
        print(f"++++\n- Added NEW FILTER list in tracker file: {new_filter_list}\n++++")
        # to test locally
        # dump_json_file(updated_tracker_data, tmp_tracker_file)
        # upload_into_s3_bucket(tmp_tracker_file, tracker_file_path, bucket_name)
        dump_json_file(updated_tracker_data, tracker_file)
        upload_into_s3_bucket(tracker_file, tracker_file_path, bucket_name)
    else:
        print(f"++++\n- New filters NOT FOUND for CVE's exist in  tracker file: {new_filter_list}\n++++")
    return new_filter_list

def find_filter_for_cves_with_no_filter(bucket_name, dv_metadata_path):
    if not os.path.exists(tracker_file):
        # loading tracker data from S3 Bucket
        tracker_data = download_file_from_s3(tracker_file, tracker_file_path, bucket_name)
    tracker_data = load_json_file(tracker_file)
    no_filter_cve_list = download_file_from_s3(no_filter_found_file, no_filter_found_path, bucket_name)
    # check for filter information of no_filter_found file
    dv_filters_dict = find_filter.main(dv_metadata_path, no_filter_cve_list, config)
    dv_filters = dv_filters_dict["filters_exist"]
    dv_filters_not_exist = dv_filters_dict["filters_does_not_exist"]
    print(f"Filters {dv_filters}")
    new_filter_list = []
    if len(dv_filters) > 0:
        updated_tracker_data, new_filter_list = tracker.parse_update_tracker_pcap(
            bucket_name, 
            dv_filters_dict,
            tracker_data, 
            config
        )
        if len(new_filter_list) > 0:
            # dump_json_file(updated_tracker_data, tmp_tracker_file)
            dump_json_file(updated_tracker_data, tracker_file)
            # put tracker file S3 Bucket
            upload_into_s3_bucket(tracker_file, tracker_file_path, bucket_name)
            # update filter does not exist file
            unique_cve_list = list(set(dv_filters_not_exist))
            # to test locally
            # dump_json_file(unique_cve_list, tmp_no_filter_found_file)
            # upload_into_s3_bucket(tmp_no_filter_found_file, no_filter_found_path, bucket_name)
            dump_json_file(unique_cve_list, no_filter_found_file)
            # put no filter for cve file S3 Bucket
            upload_into_s3_bucket(no_filter_found_file, no_filter_found_path, bucket_name)

    return new_filter_list


def download_file_from_s3(file, file_path, bucket_name):
    # create S3 object
    s3 = boto3.client('s3')
    # remove file if it exist
    if os.path.exists(file):
        print(f"-removing file {file}")
        os.remove(file)
    print("Downloading {} file from S3 Bucket {}".format(file_path, bucket_name))
    try:
        # download the tracker file from S3 bucket
        s3.download_file(bucket_name, file_path, file)
        return load_json_file(file)
    except Exception as e:
        print(f"Error downloading {file} from S3: {e}")
        return None


def load_json_file(file_name):
    if os.path.exists(file_name):
        with open(file_name) as file_object:
            file_data = json.load(file_object)
        return file_data
    raise Exception(f"File {file_name} not found!")


def dump_json_file(data, file_name):
    try:
        if os.path.exists(file_name):
            print(f"-removing file {file_name}")
            os.remove(file_name)
        # updating tracker file
        with open(file_name, "w+") as fin:
            json.dump(data, fin, indent=4)
    except Exception as e:
        print(f"Error dumping data {data} in file {file_name} with error {e}")

def upload_into_s3_bucket(file, s3_file_path, bucket_name):
    # create S3 object
    s3 = boto3.client('s3')
    print(f"file path {s3_file_path}")
    try:
        # commented for testing
        with open(file, 'rb') as file:
            s3.put_object(Bucket=bucket_name, Key=s3_file_path, Body=file)
    except Exception as e:
        print(f"Error uploading {file} to S3: {e}")



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
    new_filter_list1 = find_filter_for_cves(args.bucket_name, args.dv_metadata_path)
    new_filter_list2 = find_filter_for_cves_with_no_filter(args.bucket_name, args.dv_metadata_path)
    message = teams_notification.format_teams_message(args.build_user, args.jenkins_url, new_filter_list1,
                                                      new_filter_list2)
    # message = teams_notification.format_teams_message(new_filter_info_tracker, filter_info_no_filter,
    #                                                   teams_notification.get_pcap_folder_url(config),
    #                                                   teams_notification.get_jenkins_url(args.jenkins_url),
    #                                                   args.build_user)
    # print(f"teams message {message}")
    # send teams notification
    teams_notification.send_teams_message(args.teams_webhook_url, message)

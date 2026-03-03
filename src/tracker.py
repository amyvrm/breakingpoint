#!/usr/bin/env python3

import boto3
import json
import argparse
import os
import pprint
from typing import List, Dict, Tuple, Any
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# create aws s3 object
s3 = boto3.client('s3')

def list_objects(bucket_name: str, prefix: str = '') -> List[str]:
    s3 = boto3.client('s3')
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    objects = response.get('Contents', [])
    subfolders = [obj['Key'] for obj in objects if obj['Key'].endswith('/')]

    for folder in subfolders:
        subfolder_path = os.path.join(prefix, folder)
        objects += list_objects(bucket_name, subfolder_path)

    return objects


def parse_update_tracker_pcap(bucket_name, dv_data_dict, tracker_data, config):
    # Debugging: Check the type and content of dv_data_dict
    # print("Content of dv_data_dict:", dv_data_dict)
    pcap_prefix = config.get_bucket_prefix()
    new_filter_list = []
    tracker_cve_list_dict = tracker_data.get("tp", {})
    tracker_ds_dict = tracker_data.get("ds", {})

    # Check if dv_data_dict is in the expected format
    if not isinstance(dv_data_dict, dict) or "filters_exist" not in dv_data_dict:
        raise ValueError("dv_data_dict must be a dictionary with a 'filters_exist' key")

    for dv_dict in dv_data_dict["filters_exist"]:
        cve_id = dv_dict['cve']
        # if not check_cve_folder_exists(cve_id, bucket_name, pcap_prefix):
        #     print(f"- cve id {cve_id} not found in bucket {bucket_name}")
        #     continue
        objects = list_objects(bucket_name, f"{pcap_prefix}/{cve_id}")

        for obj_key in objects:
            pcap_uri = f"s3://{bucket_name}/{obj_key}"
            pcap_name = os.path.basename(obj_key['Key'])
            status = "unknown"
            pcap_dict = {
                pcap_name: [{
                    "status": status,
                    "s3_uri": pcap_uri,
                    "filter_id": dv_dict["id"],
                    "filter_name": dv_dict["name"],
                    "first_run": status,
                    "last_run": status
                }]
            }
            update_pcap(tracker_cve_list_dict, dv_dict, pcap_dict, pcap_name, new_filter_list)
    # returning the updated tracker file data and new filter list
    return {"tp": tracker_cve_list_dict, "ds": tracker_ds_dict}, new_filter_list


def check_cve_folder_exists(cve_num: str, bucket_name: str, pcap_prefix: str) -> bool:
    folder_prefix = f"{pcap_prefix}/{cve_num}"
    # print(f"check {cve_num} exist in S3 Bucket {folder_prefix}")
    try:
        s3 = boto3.client('s3')
        objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=folder_prefix, MaxKeys=1)
        # Check if any objects were found in the specified path
        if 'Contents' in objects:
            # print(f"Found {cve_num} in S3 Bucket {bucket_name}")
            return True
        else:
            print(f"Not Found {cve_num} in S3 Bucket {bucket_name}")
            return False
    except s3.exceptions.NoSuchBucket:
        print(f"The bucket '{bucket_name}' does not exist.")
        return False
    except (NoCredentialsError, PartialCredentialsError):
        print("Credentials not available.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def update_pcap(tracker_cve_list_dict, dv_dict, pcap_dict, pcap_name, new_filter_list):
    dv_cve = dv_dict["cve"]
    dv_filter_id = dv_dict["id"]
    filter_dict = pcap_dict[pcap_name][0]
    print(f"++++\n# Check and update {pcap_name}'s filter {dv_filter_id} entry in tracker file.\n++++")
    # check dv cve id already exist in tracker file
    if dv_cve not in tracker_cve_list_dict.keys():
        print("{} cve not found in tracker file".format(dv_cve))
        tracker_cve_list_dict[dv_cve] = [pcap_dict]
        new_filter_list.append(dv_filter_id)
        return
    elif dv_cve in tracker_cve_list_dict.keys():
        print(f"- {dv_cve} cve found in tracker file")
        t_cve_list = tracker_cve_list_dict[dv_cve]
        # all pcap of cve
        pcap_name_list = [t_pcap_name for t_pcap_dict in t_cve_list for t_pcap_name, t_pcap_info_list
                          in t_pcap_dict.items()]
        # print(f"#debug{pcap_name_list} found in {dv_cve}")
        if pcap_name in pcap_name_list:
            print(f"-- {pcap_name} found in tracker file")
            # get all filter_id exist in a pcap
            tracker_pcap_filter_list = get_all_filter_list(t_cve_list, pcap_name)
            if dv_filter_id in tracker_pcap_filter_list:
                # print(f"---- already exist, dv filter id {dv_filter_id}")
                return
            else:
                print(f"---- appending dv filter id {dv_filter_id}")
                for pcap_entry in t_cve_list:
                    if pcap_name in pcap_entry:
                        pcap_entry[pcap_name].append(filter_dict)
                        new_filter_list.append(dv_filter_id)
                        return
            raise Exception(f"Failed in updating filter detail {pcap_dict}")
        else:
            raise Exception(f"Failed in finding {dv_cve} in tracker file")


def get_all_filter_list(tracker_cve_info_list, pcap_name):
    filter_id_list = []
    # create filter id list belong to pcap under cve list
    for pcap_entry in tracker_cve_info_list:
        if pcap_name in pcap_entry:
            for filter_dict in pcap_entry[pcap_name]:
                filter_id_list.append(filter_dict["filter_id"])
    print(f"--- filter list {filter_id_list}")
    return filter_id_list


def update_tracker_file(bucket_name: str, file_key: str, local_file_path: str):
    # s3_client = boto3.client('s3')
    with open(local_file_path, 'rb') as file:
        s3.put_object(Bucket=bucket_name, Key=file_key, Body=file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--access_key_id", type=str, help="Access key id")
    parser.add_argument("--secret_key", type=str, help="Secret key")
    parser.add_argument("--bucket_name", type=str, help="Bucket name")
    args = parser.parse_args()

    boto3.setup_default_session(
        aws_access_key_id=args.access_key_id,
        aws_secret_access_key=args.secret_key,
    )
    with open("dv_filters_list_file.json") as f:
        dv_data_dict = json.load(f)

    with open("../temp/tracker_pcap.json") as f:
        tracker_data = json.load(f)

    tracker_pcap_data, new_filter_list = parse_update_tracker_pcap(args.bucket_name, dv_data_dict, tracker_data)

    with open("../temp/tracker_pcap.json", "w+") as f:
        json.dump(tracker_pcap_data, f, indent=4)

    update_tracker_file(args.bucket_name, "artefacts/tracker_pcap.json", "../temp/tracker_pcap.json")


if __name__ == "__main__":
    main()

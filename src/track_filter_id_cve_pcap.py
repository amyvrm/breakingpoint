#!/usr/bin/env python3

import boto3
import json
import argparse
import os


def list_objects(bucket_name, prefix=''):
    s3 = boto3.client('s3')
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    objects = response.get('Contents', [])
    subfolders = [obj['Key'] for obj in objects if obj['Key'].endswith('/')]

    for folder in subfolders:
        subfolder_path = os.path.join(prefix, folder)
        objects += list_objects(bucket_name, subfolder_path)

    return objects

def parse_update_tracker_pcap(bucket_name, dv_data_dict, tracker_data, pcap_prefix="pcaps"):
    new_filter_list = []
    cve_id_dict = tracker_data["tp"]
    count = 0
    for dv_dict in dv_data_dict["filters_exist"]:
        objects = list_objects(bucket_name=bucket_name, prefix="{}/{}".format(pcap_prefix, dv_dict["cve"]))
        # objects = s3.list_objects(Bucket=bucket_name, Prefix="pcaps/{}".format(dv_dict["cve"]))
        for obj in objects:
            pcap_uri = "s3://{}/{}".format(bucket_name, obj['Key'])
            pcap_name = os.path.basename(obj['Key'])
            status = "unknown"
            pcap_dict = {
                pcap_name: [
                                {
                                    "status": status,
                                    "s3_uri": pcap_uri,
                                    "filter_id": dv_dict["id"],
                                    "filter_name": dv_dict["name"],
                                    "first_run": status,
                                    "last_run": status
                                }
                ]
            }
            update_pcap(cve_id_dict, dv_dict, pcap_dict, pcap_name, new_filter_list)
            count += 1
            # formatted_json = json.dumps(cve_id_dict, indent=4)
            # print("{}. process pcap {} in file\n*".format(count, pcap_name))
    # update the trakcer file
    tracker_pcap_data = {
                            "tp": cve_id_dict,
                            "ds": {}
                        }
    return tracker_pcap_data, new_filter_list

def update_pcap(cve_id_dict, dv_dict, pcap_dict, pcap_name, new_filter_list):
    print("# {} info to be stored...".format(pcap_name))
    dv_cve = dv_dict["cve"]
    # check cve id already exist in cve_id_dict
    if dv_cve not in cve_id_dict.keys():
        print("{} cve not found in tracker file".format(dv_cve))
        cve_id_dict[dv_cve] = [pcap_dict]
        # for pcap_name, filter_info in pcap_dict.items():
        #     new_filter_list.append(filter_info[0])
        return
    elif dv_cve in cve_id_dict.keys():
        print("{} cve found in tracker file".format(dv_cve))
        for index, t_pcap_dict in enumerate(cve_id_dict[dv_cve]):
            for t_pcap_name, t_pcap_info_list in t_pcap_dict.items():
                # print("## {} iterating cve pcap list at index {}".format(t_pcap_name, index))
                if t_pcap_name == pcap_name:
                    print("{} found in tracker file".format(pcap_name))
                    for t_pcap_info in t_pcap_info_list:
                        if t_pcap_info["filter_id"] == dv_dict["id"]:
                            print("filter id already {} exist".format(t_pcap_info["filter_id"]))
                            return
                        else:
                            print("appending {} filter detail at index {}".format(pcap_dict[pcap_name][0], index))
                            cve_id_dict[dv_cve][index][pcap_name].append(pcap_dict[pcap_name][0])
                            new_filter_list.append(pcap_dict[pcap_name][0])
                            return
        print("{} not found in tracker file".format(pcap_name))
        cve_id_dict[dv_cve].append(pcap_dict)
        return

def update_tracker_file(bucket_name, file_key, local_file_path):
    s3_client = boto3.client('s3')

    with open(local_file_path, 'rb') as file:
        s3_client.put_object(Bucket=bucket_name, Key=file_key, Body=file)

def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("--access_key_id", type=str, help="Access key id ")
    parse.add_argument("--secret_key", type=str, help="Secret key")
    parse.add_argument("--bucket_name", type=str, help="Bucket name")
    args = parse.parse_args()
    # Replace with your AWS credentials and S3 bucket information
    aws_access_key_id = args.access_key_id
    aws_secret_access_key = args.secret_key
    bucket_name = args.bucket_name
    tracker_file_key = 'track_filter_id_cve_pcap.json'
    user_action = 'Performed some automated action'
    tracker_pcap_file = "tracker_pcap.json"
    file_key = "artefacts/{}".format(tracker_pcap_file)

    # Configure Boto3 with your credentials
    boto3.setup_default_session(
        aws_access_key_id = aws_access_key_id,
        aws_secret_access_key = aws_secret_access_key,
    )
    s3 = boto3.client('s3')
    with open("dv_filters_list_file.json") as fout:
        dv_data_dict = json.load(fout)
    with open("tracker_pcap.json") as fout:
        tracker_data = json.load(fout)
    # parse and update the tracker pcap file
    tracker_pcap_data = parse_update_tracker_pcap(args.bucket_name, dv_data_dict, tracker_data, s3)
    with open(tracker_pcap_file, "w+") as fin:
        json.dump(tracker_pcap_data, fin, indent=4)
    update_tracker_file(bucket_name, file_key, tracker_pcap_file)
    """
    # list objects of aws s3 bucket
    objects = list_objects(bucket_name=args.bucket_name, prefix="pcaps/CVE-2023-21554")
    for obj in objects:
        object_key = obj['Key']
        print(object_key)
    """
    # Update the tracker file with the user action
    # update_tracker_file(bucket_name, tracker_file_key, user_action)
    # print(f'Tracker file updated with user action: {user_action}')




if __name__ == "__main__":
    main()


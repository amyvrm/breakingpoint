#!/usr/bin/env python3

import json
import boto3
from lxml import etree
import argparse
from config import Config
import os
import requests


def main(dv_metadata_path, cve_list, config):
    # regular_pkg_cves = config.config["TP"]["regular_package_cves"].split("\n")
    # regular_pkg = config.config["TP"]["regular_package"]
    malware_pkg = config.config["TP"]["malware_package"]
    print("Find filter id for CVE ids {} from metadata file {}".format(cve_list, dv_metadata_path))
    # tipping point filter list for replay
    dv_filters_dict = {}
    dv_filters = []
    # read the metadata file
    tree = etree.parse((dv_metadata_path))
    root = tree.getroot()
    # get all filters
    tp_filters = root.findall('filters/filter')
    # iterate and find filters
    for tp_filter in tp_filters:
        tp_filter_id = tp_filter.get('id')
        for cve in tp_filter.findall(".//cve"):
            cve_id = cve.get("id")
            tp_filter_src = tp_filter.get('src')
            if tp_filter_src == malware_pkg:
                continue
            tp_filter_name = tp_filter.find('./meta/name').text
            if cve_id in cve_list:
                for bp_cve in cve_list:
                    if cve_id == bp_cve:
                        print("{0}\nAdd filter id {1}, cve {2} filter name {3}\n{0}".format("-" * 50, tp_filter_id,
                                                                                        cve_id, tp_filter_name))
                        dv_filters.append({'id': tp_filter_id, 'name': tp_filter_name, 'cve': cve_id})
    dv_filters_cves = [filter["cve"] for filter in dv_filters]
    filter_does_not_exist = [cve_id for cve_id in cve_list if cve_id not in dv_filters_cves]
    # found filter id list
    dv_filters_dict["filters_exist"] = dv_filters
    dv_filters_dict["filters_does_not_exist"] = filter_does_not_exist
    print("dv filters dict {}".format(dv_filters_dict))
    # dump dv_filters data into json file
    return dv_filters, dv_filters_dict

def dowload_new_cve_list(new_cve_list_file, access_key_id, aws_secret_key, bucket_name):
    s3 = boto3.client('s3', aws_access_key_id=access_key_id, aws_secret_access_key=aws_secret_key)
    if os.path.exists(new_cve_list_file):
        os.remove(new_cve_list_file)
    s3.download_file(bucket_name, new_cve_list_file, new_cve_list_file)
    # print(os.listdir())
    return load_new_cve_list(new_cve_list_file)

def load_new_cve_list(new_cve_list_file):
    with open(new_cve_list_file, "r") as fout:
        new_cve_dict = json.load(fout)
    new_cve_list = new_cve_dict['cve']
    print("New CVE ids {}".format(new_cve_list))
    if len(new_cve_list) > 0:
        return new_cve_list
    else:
        return False

def dump_into_json_file(data, file):
    if os.path.exists(file):
        os.remove(file)
    with open(file, "w") as fin:
        json.dump(data, fin, indent=4)

def get_s3_list_ids(access_key_id, aws_secret_key, bucket_name):
    cve_list = []
    s3 = boto3.resource('s3', aws_access_key_id=access_key_id, aws_secret_access_key=aws_secret_key)
    bucket = s3.Bucket(bucket_name)
    result = bucket.meta.client.list_objects(Bucket=bucket.name, Delimiter='/')
    for obj in result.get('CommonPrefixes'):
        cve_id = obj.get('Prefix').replace("/", "")
        print("+ adding cve id {}".format(cve_id))
        cve_list.append(cve_id)
    return cve_list

def jfrog_upload_json_file(file, jfrog_url_target, jfrog_token):
    jfrog_url = "{}/{}".format(jfrog_url_target, file)
    # read the file
    with open(file, "r") as fout:
        dict_file = json.load(fout)
        mal_data_json = json.dumps(dict_file, indent=4)
        # upload the file
        # res = requests.put(jfrog_url, data=fout.read(), headers={'Authorization': 'Bearer ' + jfrog_token})
        res = requests.put(jfrog_url, data=mal_data_json, headers={'X-JFrog-Art-Api': jfrog_token})
        print("Jfrog_upload status: {}".format(res.status_code))
        if res.status_code == 201:
            print("Suceeded in {} file Uploaded in JFrog...".format(file))
        else:
            print("FAILED in {} file Uploaded in JFrog...".format(file))
    return jfrog_url

def send_teams_notification(webhook, file_url, jenkins_build, build_user):
    jenkins_info = jenkins_build.split("/")
    message = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "00ff00",
        "summary": "Nessus Scan Report",
        "sections":
            [
                {
                    "activityTitle": "Tipping-Point Operation",
                    "activitySubtitle": "Build: {} - {}".format(jenkins_info[-3], jenkins_info[-2]),
                    "activityImage": "https://teamsnodesample.azurewebsites.net/static/img/image5.png",
                    "facts":
                        [
                            {
                                "name": "Get Filter id from CVE Status",
                                "value": "Success"
                            },
                            {
                                "name": "Build User",
                                "value": build_user
                            }
                        ],
                    "markdown": True
                }
            ],
        "potentialAction":
            [
                {
                    "@type": "OpenUri",
                    "name": "CVE-Filter id mapping file url",
                    "targets":
                        [
                            {
                                "os": "default",
                                "uri": file_url
                            }
                        ]
                },
                {
                    "@type": "OpenUri",
                    "name": "View Jenkins Build",
                    "targets":
                        [
                            {
                                "os": "default",
                                "uri": jenkins_build
                            }
                        ]
                }
            ]
    }
    # define header type
    headers = {'content-type': 'application/json'}
    # send the teams message
    requests.post(webhook, data=json.dumps(message), headers=headers)




if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument("--dv_metadata_path", type=str, help="Please dv metadata path")
    parse.add_argument("--access_key_id", type=str, help="Access key id ")
    parse.add_argument("--secret_key", type=str, help="Secret key")
    parse.add_argument("--bucket_name", type=str, help="Bucket name")
    parse.add_argument("--jfrog_url", type=str, help="jfrog url")
    parse.add_argument("--jfrog_token", type=str, help="jfrog token")
    parse.add_argument("--jenkins_url", type=str, help="Jenkins build url")
    parse.add_argument("--build_user", type=str, help="Build user")
    parse.add_argument("--teams_webhook", type=str, help="Jenkins webhook")
    args = parse.parse_args()
    # load config file
    conf_file = "config/.config.ini"
    config = Config(conf_file)
    # get new cve list
    new_cve_list_file = config.get_new_cve_list_file()
    dv_filters_list_file = config.get_dv_filters_list_file()
    # get the list of cve_id
    cve_list = dowload_new_cve_list(new_cve_list_file, args.access_key_id, args.secret_key, args.bucket_name)
    if cve_list:
        dv_filters, dv_filters_dict = main(args.dv_metadata_path, cve_list, config)
        dump_into_json_file(dv_filters_dict, dv_filters_list_file)
        s3 = boto3.client('s3', aws_access_key_id=args.access_key_id, aws_secret_access_key=args.secret_key)
        s3.upload_file(dv_filters_list_file, args.bucket_name, dv_filters_list_file)
        response = s3.head_object(Bucket=args.bucket_name, Key=dv_filters_list_file)
        print(response)
        object_arn = response['ARN']
        print("DV Filters: {} and ARN {}".format(dv_filters, response))
        send_teams_notification(args.teams_webhook, object_arn, args.jenkins_url, args.build_user)
    else:
        raise Exception("Error! cve id not found")
    # upload the dv_filters into file
    # jfrog_url = jfrog_upload_json_file(dv_filters_list_file, args.jfrog_url, args.jfrog_token)
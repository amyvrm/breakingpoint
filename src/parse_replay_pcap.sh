#!/bin/bash

# credential and parameters
#json_file="new_tracker_pcap.json"
json_file="tracker_pcap.json"
cve_folder="${1}"
user="${2}"
password="${3}"
tp_ip="10.203.202.61"
artefacts_folder="artefacts"
s3_bucket_arn="s3://dvlabs-breakingpoint-pcaps-test"
timestamp=$(date +"%Y%m%d%H%M%S")
# download tracker file
echo "Downloading json file $json_file"
aws s3 cp "$s3_bucket_arn/$artefacts_folder/$json_file" "$json_file"
json_data=$(cat "$json_file")
# get the present working directory
current_dir=$(pwd)
# create artefact folder for test report
if [ -d "$artefacts_folder" ]; then
  echo "$artefacts_folder folder already exist"
else
  # create the folder if it doesn't exist
  mkdir -p "$current_dir/$artefacts_folder"
  echo "$artefacts_folder folder created"
fi

# create test report
report_file="$current_dir/$artefacts_folder/test_report.txt"
if [ -f "$report_file" ]; then
  echo "file exist...removing it"
  rm "$report_file"
else
  # create a file in the current working directory
  echo "'$report_file' file created"
fi

if sudo -n true 2>/dev/null; then
  SUDO="sudo"
 else
   SUDO=""
fi

set_up_tp() {
  echo "set up tp for first time"
  command_output=$(sshpass -p "${password}" ssh -t "${user}"@"${tp_ip}" << EOF
sms unmanage
edit
ips
virtual-segments
display
exit
ips
profile "Default, 6.0"
categoryrule
category "Streaming Media" disabled
category "Identity Theft" disabled
category "Virus" disabled
category "Spyware" disabled
category "IM" disabled
category "Network Equipment" disabled
category "Traffic Normalization" disabled
category "P2P" disabled
category "Vulnerabilities" disabled
category "Exploits" disabled
category "Reconnaissance" disabled
category "Security Policy" disabled
exit
exit
exit
commit
exit
clear log-file ipsAlert
logout
EOF
)
  echo "output: $command_output"
}

set_up_tp_with_rule() {
  local cve_id=$1
  local filter_id=$2
  echo "set up tp for first time and enable filter id $filter_id"
  command_output=$(sshpass -p "${password}" ssh -t "${user}"@"${tp_ip}" << EOF
sms unmanage
edit
ips
virtual-segments
display
exit
ips
profile "Default, 6.0"
filter $filter_id
actionset "Permit + Notify"
enable
exit
categoryrule
category "Streaming Media" disabled
category "Identity Theft" disabled
category "Virus" disabled
category "Spyware" disabled
category "IM" disabled
category "Network Equipment" disabled
category "Traffic Normalization" disabled
category "P2P" disabled
category "Vulnerabilities" disabled
category "Exploits" disabled
category "Reconnaissance" disabled
category "Security Policy" disabled
exit
exit
exit
commit
exit
clear log-file ipsAlert
logout
EOF
)
  echo "output: $command_output"
}

disable_filter() {
  local filter_id=$1
  echo "disale filter id $filter_id"
  command_output=$(sshpass -p "${password}" ssh -t "${user}"@"${tp_ip}" << EOF
edit
ips
profile "Default, 6.0"
filter $filter_id
disable
exit
commit
exit
exit
exit
logout
EOF
)
  echo "output: $command_output"
}

run_next_filter() {
  local cve_id=$1
  local filter_id=$2
  echo "Enable next filter id $filter_id"
  command_output=$(sshpass -p "${password}" ssh -t "${user}"@"${tp_ip}" << EOF
edit
ips
profile "Default, 6.0"
filter $filter_id
actionset "Permit + Notify"
enable
exit
commit
exit
exit
exit
clear log-file ipsAlert
logout
EOF
)
  echo "output: $command_output"
}

download_pcaps() {
  local cve_id=$1
  cd "$cve_folder"
  echo "download pcaps for cve id $cve_id in folder pcaps"
  # Create folder if cve id folder does not exist
  if [ ! -d "$cve_id" ]; then
    echo "Downloading..."
    aws s3 sync "$s3_bucket_arn/pcaps/$cve_id" "$cve_id"
  fi
}

download_pcap_file() {
  local pcap_name=$1
  local pcaps_folder=$2
  local s3_uri=$3
  echo "changing directory $cve_folder"
  cd "$cve_folder"
  # pcap full pcap file with path
  pcap_path="${pcaps_folder}/${pcap_name}"
  if [ -f "$pcap_path" ]; then
    echo "$pcap_path already exist"
  else
    echo "cmd: aws s3 cp $s3_uri $pcap_path"
    echo "Downloading..."
    aws s3 cp "$s3_uri" "$pcap_path"
  fi
}

download_pcap_replay() {
  local cve_id=$1
  local pcap_name=$2
  local s3_uri=$3
  local filter_id=$4
  local filter_name=$5
  local pcaps_folder=$6
  echo "changing directory $cve_folder"
  cd "$cve_folder"
  # pcap full pcap file with path
  pcap_path="${pcaps_folder}/${pcap_name}"
  if [ -f "$pcap_path" ]; then
    echo "{} already exist"
    replay_pcap_file "$cve_id" "$pcap_name" "$filter_id" "$filter_name" "$pcaps_folder"
  else
    echo "Downloading $s3_uri"
    echo "To $pcap_path..."
    aws s3 cp "$s3_uri" "$pcap_path"
    replay_pcap_file "$cve_id" "$pcap_name" "$filter_id" "$filter_name" "$pcaps_folder"
  fi
}

iterate_pcap() {
  local cve_id=$1
  local pcaps_folder=$2
  local filter_id=$3
  local name=$4
  echo "iterate pcap for cve id $cve_id"
  cd "$cve_folder"
  # Check if the folder exists
  if [ -d "$cve_id" ]; then
    # Iterate through each file in the folder
    for protocol_folder in "$cve_id"/*; do
      # Check if it is a regular file (not a directory)
      if [ -d "$protocol_folder" ]; then
        echo "protocol folder $protocol_folder"
        # Iterate through each protocol file in the folder
        for pcap_file in "$protocol_folder"/*; do
          echo "Pcap file: $pcap_file"
          replay_pcap "$pcap_file" "$pcaps_folder" "$filter_id" "$name" "$cve_id"
          # break
        done
      elif [ -f "$protocol_folder" ]; then
          echo "protocol file $protocol_folder found"
          replay_pcap "$pcap_file" "$pcaps_folder" "$filter_id" "$name" "$cve_id"
      else
        echo "Protocol folder does not exist"
      fi
    done
  else
    echo "CVE pcap folder does not exist: $cve_id" "$filter_id"
  fi
}

replay_pcap() {
  local pcap_file=$1
  local pcap_file_name=$(basename "$pcap_file")
  local fcs_fix_pcap="$2/wo_mac_$pcap_file_name"
  local filter_id=$3
  local name=$4
  local cve_id=$5
  local pcap="$2/$pcap_file_name"
  cd "$cve_folder"
  echo "replay pcap file $pcap_file, fix fcs $fcs_fix_pcap for filter id $filter_id"
  # Do this one before uploading to S3:
  tcprewrite -E -C -i "$pcap_file" -o "$fcs_fix_pcap"
  tcprewrite --enet-smac=00:50:56:83:61:a4 --enet-dmac=00:50:56:83:64:35 -i "$fcs_fix_pcap" -o "$pcap"
  echo "$password" | sudo -S tcpreplay -i ens224 -M 5 "$pcap"
  sleep 5
  check_event_tp "$filter_id" "$name" "$pcap_file" "$cve_id"
  cd ..
}

replay_pcap_file() {
  # command line variables
  local cve_id=$1
  local pcap_name=$2
  local filter_id=$3
  local filter_name=$4
  local pcaps_folder=$5
  # new variables
  # pcap_path="$pcaps_folder/$pcap_name"
  # fix_fcs_pcap="$pcaps_folder/fix_fcs_$pcap_name"
  fix_fcs_pcap="$pcaps_folder/$pcap_name"
  fix_mac_pcap="$pcaps_folder/fix_mac_$pcap_name"
  # change directory
  cd "$cve_folder"
  # echo "fix fcs for pcap $pcap_path"
  # echo "create new pcap $fix_fcs_pcap"
  # tcprewrite -E -C -i "$pcap_path" -o "$fix_fcs_pcap"
  # echo "fixing mac for esxi $fix_fcs_pcap"
  echo "create new pcap $fix_mac_pcap"
  tcprewrite --enet-smac=00:50:56:83:61:a4 --enet-dmac=00:50:56:83:64:35 -i "$fix_fcs_pcap" -o "$fix_mac_pcap"
  echo "replay fixed mac pcap $fix_mac_pcap"
  echo "$password" | sudo -S tcpreplay -i ens224 -M 5 "$fix_mac_pcap"
  sleep 5
  check_event_tp "$filter_id" "$filter_name" "$pcap_name" "$cve_id"
  cd ..
}

check_event_tp() {
  local filter_id=$1
  local filter_name=$2
  local pcap_name=$3
  local cve_id=$4
  echo "checking ips alert for filter id $filter_id"
# Run your command-line application and store the output in a variable
command_output=$(sshpass -p "${password}" ssh -t "${user}"@"${tp_ip}" << EOF
show log-file ipsAlert
logout
EOF
)
  # Print the command output
  echo "$command_output"
  # Search pattern
  search_pattern="$filter_id: $filter_name"
  # Check if the search pattern exists in the command output
  if echo "$command_output" | grep -qF "$search_pattern"; then
      echo "Alert found for the pcap $pcap_name and $filter_id."
      echo "Test Pass !"
      data="$cve_id - $pcap_name - $filter_id - $filter_name - pass - $timestamp"
      echo "$data" >> "$report_file"
      echo "---"
  else
      echo "Alert not found for the pcap $pcap_name and $filter_id."
      echo "Test Failed !"
      data="$cve_id - $pcap_name - $filter_id - $filter_name - fail - $timestamp"
      echo "$data" >> "$report_file"
      echo "***"
  fi
}

upload_file_s3() {
  local file_path=$1
  local folder=$2
  # copy the report in se bucket
  if [ -f "$file_path" ]; then
    file_name=$(basename "$file_path")
    aws s3 cp "$file_path" "$s3_bucket_arn/artefacts/$folder/$file_name"
    echo "$s3_bucket_arn/artefacts/$folder/$file_name file copied in AWS S3 bucket"
  else
    echo "$file_path file not found!"
  fi
}

pcaps_folder_path="$cve_folder/toreplay"
# create artefact folder for test report
if [ -d "$pcaps_folder_path" ]; then
  echo "$pcaps_folder_path folder already exist, removing it..."
  rm -rf $pcaps_folder_path
  # create the folder
  mkdir -p "$pcaps_folder_path"
else
  # create the folder
  mkdir -p "$pcaps_folder_path"
fi
echo "$artefacts_folder folder created"
folder_name=$(basename "$cve_folder")
pcaps_folder="toreplay"
# setup the tp box
set_up_tp
# Extract each section and its data
sections=$(echo "$json_data" | jq -c 'keys[]')
# Iterate over each section
for section in $sections; do
    echo "section: $section"
    section_data=$(echo "$json_data" | jq -r ".$section")
#    echo "section_data: $section_data"
    cves_list=$(echo "$section_data" | jq -c 'keys[]')
    for cve_id in $cves_list; do
      echo "cve id: $cve_id"
      cve_list_data=$(echo "$json_data" | jq -r ".$section.$cve_id")
#      echo "cve list data: $cve_list_data"
      pcaps=$(echo "$cve_list_data" | jq -c '.[]')
      pcap_info=$(echo "$pcaps" | jq -c 'keys[]')
#      echo "pcap info: $pcap_info"
      for pcap_name in $pcap_info; do
        # Remove double quotes using tr command
        cve_id_cleaned=$(echo "$cve_id" | tr -d '"')
        pcap_name_cleaned=$(echo "$pcap_name" | tr -d '"')
#        echo "$pcap_name"
        jq_command=".${section}.${cve_id}[] | .${pcap_name} // empty"
        # Execute jq command
        pcap_filter_data_list=$(jq -r "$jq_command" "$json_file")
        pcap_filter_data=$(echo "$pcap_filter_data_list" | jq -c '.[]')
        echo "$pcap_filter_data" | jq -r '"\(.status),\(.s3_uri),\(.filter_id),\(.filter_name)"' |
        while IFS= read -r filter_info; do
          status=$(echo "$filter_info" | cut -d ',' -f1)
          s3_uri=$(echo "$filter_info" | cut -d ',' -f2)
          filter_id=$(echo "$filter_info" | cut -d ',' -f3)
          filter_name=$(echo "$filter_info" | cut -d ',' -f4)
          echo "$cve_id_cleaned, $pcap_name_cleaned, $status, $s3_uri, $filter_id, $filter_name"
          if [ "$status" == "unknown" ] || [ "$status" == "fail" ]; then
            echo "status: $status"
            run_next_filter "$cve_id_cleaned" "$filter_id"
            download_pcap_file "$pcap_name_cleaned" "$pcaps_folder" "$s3_uri"
            replay_pcap_file "$cve_id_cleaned" "$pcap_name_cleaned" "$filter_id" "$filter_name" "$pcaps_folder"
#            download_pcap_replay "$cve_id_cleaned" "$pcap_name_cleaned" "$s3_uri" "$filter_id" "$filter_name" "$pcaps_folder"
            disable_filter "$filter_id"
          fi
        done
        echo "-"
      done
      echo "-------------"
    done
done
python3 update_tracker_file.py --test_report "$report_file" --tracker_file "$json_file"
aws s3 cp "$json_file" "$s3_bucket_arn/$artefacts_folder/$json_file"

#!/bin/bash


set_up_tp() {
  local cve_id=$1
  local filter_id=$2
  echo "set up tp for first time and enable filter id $filter_id"
  command_output=$(sshpass -p "Hqlocal1!" ssh SuperUser@10.203.202.61 << EOF
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
  command_output=$(sshpass -p "Hqlocal1!" ssh SuperUser@10.203.202.61 << EOF
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
  command_output=$(sshpass -p "Hqlocal1!" ssh SuperUser@10.203.202.61 << EOF
edit
ips
profile "Default, 6.0"
filter "$filter_id"
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
  local pcaps_folder=$2
  cd /home/testuser/Downloads/pcaps
  echo "download pcaps for cve id $cve_id in folder $pcaps_folder"
  # Create folder if cve id folder does not exist
  if [ ! -d "$cve_id" ]; then
    mkdir "$cve_id"
    cd "$cve_id"
    aws s3 sync "s3://dvlabs-breakingpoint-pcaps-poc/pcaps/$cve_id" "$cve_id"
    mkdir "$cve_id/$pcaps_folder"
  fi
}

iterate_pcap() {
  local cve_id=$1
  local pcaps_folder=$2
  local filter_id=$3
  echo "iterate pcap for cve id $cve_id"
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
          replay_pcap "$pcap_file"
        done
      elif [ -f "$protocol_folder" ]; then
          echo "protocol file $protocol_folder found"
          replay_pcap "$pcap_file" "$pcaps_folder" "$filter_id"
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
  local fcs_fix_pcap="$2/wo_mac_$pcap_file"
  local filter_id=$3
  local pcap="$2/$pcap_file"
  cd /home/testuser/Downloads/pcaps
  echo "replay pcap file $pcap_file, fix fcs $fcs_fix_pcap for filter id $filter_id"
  # Do this one before uploading to S3:
  tcprewrite -E -C -i "$pcap_file" -o "$fcs_fix_pcap"
  tcprewrite --enet-smac=00:50:56:83:61:a4 --enet-dmac=00:50:56:83:64:35 -i "$fcs_fix_pcap" -o "$pcap"
  sudo tcpreplay -i ens224 -M 5 "$pcap"
  sleep 5
  check_event_tp "$filter_id"
}

check_event_tp() {
  local filter_id=$1
  echo "if filter id $filter_id not found in alert log then create/update jira case"
# Run your command-line application and store the output in a variable
command_output=$(sshpass -p Hqlocal1! ssh SuperUser@10.203.202.61 << EOF
show log-file ipsAlert
logout
EOF
)
  # Print the command output
  echo "$command_output"
  # Check if the string is present in the output using grep
  if echo "$command_output" | grep -q "$filter_id"; then
      echo "Filter id '$filter_id' found in the TP."
  else
      echo "Filter id '$filter_id' not found in the TP."
  fi
}

# Read the JSON file and parse it using jq
json_file="dv_filters_list_file.json"
cd /home/testuser/Downloads/pcaps
pcaps_folder="toreplay"
rm -rf $pcaps_folder
mkdir $pcaps_folder
# Flag to check if the function has been executed
executed=false
jq -r '.filters_exist[] | "\(.id), \(.name), \(.cve)"' "$json_file" |
while IFS= read -r filter_info; do
#    echo "Filter Info: $filter_info"
    id=$(echo "$filter_info" | cut -d ',' -f1)
    name_space=$(echo "$filter_info" | cut -d ',' -f2)
    # Remove leading spaces
    name="${name_space#"${name_space%%[![:space:]]*}"}"
    cve_space=$(echo "$filter_info" | cut -d ',' -f3)
    cve="${cve_space#"${cve_space%%[![:space:]]*}"}"
#    echo "id-$id name-$name cve-$cve"
    cve_id="$cve"
    filter_id="$id"
    # Check if the function has not been executed
    if [ "$executed" = false ]; then
        set_up_tp "$cve_id" "$filter_id"
        executed=true  # Set the flag to true after executing the function
    else
        run_next_filter "$cve_id" "$filter_id"
    fi
    download_pcaps "$cve_id" "$pcaps_folder"
    iterate_pcap "$cve_id" "$pcaps_folder" "$filter_id"
    disable_filter "$filter_id"
done
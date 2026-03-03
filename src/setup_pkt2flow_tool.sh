#!/bin/bash

tool_name="pkt2flow"

sudo yum install -y libpcap-devel.x86_64
sudo yum install -y git
sudo yum install -y gcc
pip3 install SCons==4.6.0
git clone https://github.com/caesar0301/pkt2flow.git
cd $tool_name

# Specify the file name
file1="pkt2flow.c"
file2="utilities.c"
file3="flow_db.c"

# Define the new line to be added
new_line='#define _GNU_SOURCE'
search_line='struct ip_pair *pairs [HASH_TBL_SIZE];'
line_pattern="struct ip_pair \*pairs \[HASH_TBL_SIZE\];"

# Use sed to add the new line after the existing line
#sed -i "/#include \"pkt2flow.h\"/a$new_line" "$file1"
#sed -i "/#include \"pkt2flow.h\"/a$new_line" "$file2"
#sed -i "/$search_line/a#$search_line" "$file3"
sed -i "1i$new_line" "$file1"
sed -i "1i$new_line" "$file2"
sed -i "s|$line_pattern|// $line_pattern|" "$file3"
sleep 5
scons
ls -la
sudo cp -r $tool_name /tmp/dep/.
sudo chmod +r /tmp/dep/$tool_name
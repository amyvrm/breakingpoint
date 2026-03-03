#!/bin/bash

aws configure set aws_access_key_id $1 --profile $4
aws configure set aws_secret_access_key $2 --profile $4
aws configure set region $3 --profile $4
aws configure set output json --profile $4
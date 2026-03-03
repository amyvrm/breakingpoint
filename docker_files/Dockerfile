FROM python:3.12.0a2-bullseye

RUN apt-get update -y && apt-get install -y unzip wget && useradd -s /bin/bash -u 501 -U -d /build -m build && groupmod -g 501 build
#RUN curl https://releases.hashicorp.com/terraform/1.2.6/terraform_1.2.6_linux_amd64.zip -o terraform.zip && unzip terraform.zip -d /usr/local/bin
RUN curl https://releases.hashicorp.com/terraform/1.6.6/terraform_1.6.6_linux_amd64.zip -o terraform.zip && unzip terraform.zip -d /usr/local/bin
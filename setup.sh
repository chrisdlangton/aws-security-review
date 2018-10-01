#!/usr/bin/env bash

AWS_ACCESS_KEY_ID=$(aws --profile chris configure get aws_access_key_id)
AWS_SECRET_ACCESS_KEY=$(aws --profile chris configure get aws_secret_access_key)

docker build . --force-rm --compress -t chrisdlangton/aws-sec-scan

docker run -ti \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -v "`pwd`/src:/app/src:rw" \
  chrisdlangton/aws-sec-scan

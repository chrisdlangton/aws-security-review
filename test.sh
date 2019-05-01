#!/usr/bin/env bash

AWS_ACCESS_KEY_ID=$(aws --profile chris configure get aws_access_key_id)
AWS_SECRET_ACCESS_KEY=$(aws --profile chris configure get aws_secret_access_key)

FILE=$1
if [ -z "${FILE}" ]; then
  echo "specify a file to test, e.g. src/main.py"
  exit 1
fi

docker run -ti \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -v "`pwd`/src:/app/src:rw" \
  -v "${HOME}/.aws:/app/.aws:ro" \
  chrisdlangton/aws-security-scan ${FILE}

exit $?

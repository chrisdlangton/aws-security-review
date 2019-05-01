#!/usr/bin/env bash

AWS_ACCESS_KEY_ID=$(aws --profile chris configure get aws_access_key_id)
AWS_SECRET_ACCESS_KEY=$(aws --profile chris configure get aws_secret_access_key)

if test "$#" -lt 1; then
  echo "specify a file to test, e.g. src/main.py"
  exit 1
fi

docker run -ti --rm \
  --name aws-security-review \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -v "`pwd`/src:/app/src:rw" \
  -v "${HOME}/.aws:/app/.aws:ro" \
  chrisdlangton/aws-security-scan $@

exit $?

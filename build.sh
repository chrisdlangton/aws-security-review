#!/usr/bin/env bash
docker build . --force-rm --compress -t chrisdlangton/aws-security-scan $@
exit $?

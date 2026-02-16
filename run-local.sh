#!/bin/bash

set -eo pipefail

OPERATOR_NAMESPACE=${OPERATOR_NAMESPACE:-openshift-oauth-account-operator}
export OPERATOR_NAMESPACE

cd ./operator

exec kopf run \
  --standalone \
  --all-namespaces \
  --liveness=http://0.0.0.0:8080/healthz \
  operator.py

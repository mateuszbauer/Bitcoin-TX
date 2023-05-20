#!/bin/bash

curl -H "Accept: application/json; indent=4" https:/bitnodes.io/api/v1/snapshots/latest/ | grep ':8333' | head -20 | awk -F'"' '{print $2}'

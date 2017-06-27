#!/bin/bash

chef_org="$1"
echo "${chef_org}"
# Remove any whitespace from Company name
chef_orgConcat="$(echo -e "${chef_org}" | tr -d '[:space:]')"
echo "${chef_orgConcat}"

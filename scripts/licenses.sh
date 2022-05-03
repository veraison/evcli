#!/bin/bash

set -e

type go-licenses &> /dev/null || go get github.com/google/go-licenses

MODULES+=("github.com/veraison/evcli/cmd")
MODULES+=("github.com/veraison/evcli/cmd/psa")
MODULES+=("github.com/veraison/evcli/common")

for module in ${MODULES[@]}
do
  echo ">> retrieving licenses [ ${module} ]"
  go-licenses csv ${module}
done

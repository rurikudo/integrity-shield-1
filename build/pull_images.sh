#!/bin/bash
#
# Copyright 2020 IBM Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


if ! [ -x "$(command -v docker)" ]; then
    echo 'Error: docker is not installed.' >&2
    exit 1
fi


if [ -z "$IV_SERVER_IMAGE_NAME_AND_VERSION" ]; then
    echo "IV_SERVER_IMAGE_NAME_AND_VERSION is empty. Please set iv build env settings."
    exit 1
fi

if [ -z "$IV_LOGGING_IMAGE_NAME_AND_VERSION" ]; then
    echo "IV_LOGGING_IMAGE_NAME_AND_VERSION is empty. Please set iv build env settings."
    exit 1
fi

if [ -z "$IV_OPERATOR_IMAGE_NAME_AND_VERSION" ]; then
    echo "IV_OPERATOR_IMAGE_NAME_AND_VERSION is empty. Please set iv build env settings."
    exit 1
fi



# Pull integrity-verifier-server image
echo -----------------------------
echo [1/3] Pulling integrity-verifier-server image.
docker pull ${IV_SERVER_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""


# Push integrity-verifier-logging image
echo -----------------------------
echo [2/3] Pulling integrity-verifier-logging image.
docker pull ${IV_LOGGING_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""

# Push integrity-verifier-operator image
echo -----------------------------
echo [3/3] Pulling integrity-verifier-operator image.
docker pull ${IV_OPERATOR_IMAGE_NAME_AND_VERSION}
echo done.
echo -----------------------------
echo ""

echo Completed.
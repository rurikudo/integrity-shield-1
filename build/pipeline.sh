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

set -e

echo "IMAGE PUBLISH GOES HERE!"

echo "Pipeline for integrity shield starting : $(date)"

export COMPONENT_VERSION=${ISHIELD_VERSION}
export COMPONENT_DOCKER_REPO=${REGISTRY}

# Publish ${ISHIELD_IMAGE}
export COMPONENT_NAME=${ISHIELD_IMAGE}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
rm -rf pipeline
make pipeline-manifest/update PIPELINE_MANIFEST_COMPONENT_SHA256=${TRAVIS_COMMIT} PIPELINE_MANIFEST_COMPONENT_REPO=${TRAVIS_REPO_SLUG} PIPELINE_MANIFEST_BRANCH=${TRAVIS_BRANCH}
echo "Completed pipeline for integrity shield component: $COMPONENT_NAME"

# Publish ${ISHIELD_REPORTER}
export COMPONENT_NAME=${ISHIELD_REPORTER}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
rm -rf pipeline
make pipeline-manifest/update PIPELINE_MANIFEST_COMPONENT_SHA256=${TRAVIS_COMMIT} PIPELINE_MANIFEST_COMPONENT_REPO=${TRAVIS_REPO_SLUG} PIPELINE_MANIFEST_BRANCH=${TRAVIS_BRANCH}
echo "Completed pipeline for integrity shield component: $COMPONENT_NAME"

# Publish ${ISHIELD_OBSERVER}
export COMPONENT_NAME=${ISHIELD_OBSERVER}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
rm -rf pipeline
make pipeline-manifest/update PIPELINE_MANIFEST_COMPONENT_SHA256=${TRAVIS_COMMIT} PIPELINE_MANIFEST_COMPONENT_REPO=${TRAVIS_REPO_SLUG} PIPELINE_MANIFEST_BRANCH=${TRAVIS_BRANCH}
echo "Completed pipeline for integrity shield component: $COMPONENT_NAME"

# Publish ${ISHIELD_ADMISSION_CONTROLLER}
export COMPONENT_NAME=${ISHIELD_ADMISSION_CONTROLLER}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
rm -rf pipeline
make pipeline-manifest/update PIPELINE_MANIFEST_COMPONENT_SHA256=${TRAVIS_COMMIT} PIPELINE_MANIFEST_COMPONENT_REPO=${TRAVIS_REPO_SLUG} PIPELINE_MANIFEST_BRANCH=${TRAVIS_BRANCH}
echo "Completed pipeline for integrity shield component: $COMPONENT_NAME"

# Publish ${ISHIELD_OPERATOR}
export COMPONENT_NAME=${ISHIELD_OPERATOR}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
rm -rf pipeline
make pipeline-manifest/update PIPELINE_MANIFEST_COMPONENT_SHA256=${TRAVIS_COMMIT} PIPELINE_MANIFEST_COMPONENT_REPO=${TRAVIS_REPO_SLUG} PIPELINE_MANIFEST_BRANCH=${TRAVIS_BRANCH}
echo "Completed pipeline for integrity shield component: $COMPONENT_NAME"

# Publish ${ISHIELD_BUNDLE}
export COMPONENT_NAME=${ISHIELD_BUNDLE}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
rm -rf pipeline
make pipeline-manifest/update PIPELINE_MANIFEST_COMPONENT_SHA256=${TRAVIS_COMMIT} PIPELINE_MANIFEST_COMPONENT_REPO=${TRAVIS_REPO_SLUG} PIPELINE_MANIFEST_BRAN>echo "Completed pipeline for integrity shield component: $COMPONENT_NAME"

# Publish ${ISHIELD_INDEX}
export COMPONENT_NAME=${ISHIELD_INDEX}
export DOCKER_IMAGE_AND_TAG=${COMPONENT_DOCKER_REPO}/${COMPONENT_NAME}:${COMPONENT_VERSION}${COMPONENT_TAG_EXTENSION}
rm -rf pipeline
make pipeline-manifest/update PIPELINE_MANIFEST_COMPONENT_SHA256=${TRAVIS_COMMIT} PIPELINE_MANIFEST_COMPONENT_REPO=${TRAVIS_REPO_SLUG} PIPELINE_MANIFEST_BRAN>

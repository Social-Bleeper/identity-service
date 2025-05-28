#!/usr/bin/env bash

set -e

eval $(minikube docker-env)

IMAGE_TAG="bleeper-identity-service"
VERSION="${1-latest}"

# script takes an optional tag argument, otherwise uses "latest"
docker build \
    -f Dockerfile \
    -t "$IMAGE_TAG:$VERSION" .

echo "$IMAGE_TAG:$VERSION"

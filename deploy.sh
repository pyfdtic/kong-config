#!/bin/bash
#

IMG_REPO="registry.pyfdtic.com/infra/kong-config"
IMG_TAG="v0.1.0"

make docker-build docker-push IMG=$IMG_REPO:$IMG_TAG && \
make deploy IMG=$IMG_REPO:$IMG_TAG

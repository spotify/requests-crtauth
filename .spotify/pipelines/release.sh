#!/bin/bash -e

# TODO(negz): Remove when https://ghe.spotify.net/supermario/buildbricks/pull/58 is merged
export DEVPI_INDEX="https://pypi.spotify.net/spotify/production"

if git describe --exact-match 2> /dev/null; then
    export PBR_VERSION=$(git describe)
else
    export PBR_VERSION=$(git describe | sed -E 's/([0-9]+)\.([0-9]+)-([0-9]+).*/\1.\2.\3/')
fi

sp-pypi-upload

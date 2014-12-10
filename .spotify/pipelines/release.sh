#!/bin/bash -e

if git describe --exact-match 2> /dev/null; then
    VERSION=$(git describe)
else
    VERSION=$(git describe | sed -E 's/([0-9]+)\.([0-9]+)-([0-9]+).*/\1.\2.\3/')
    git tag -a "$VERSION" -m "Tagging version \"${VERSION}\""
fi

python setup.py sdist; scp -o StrictHostKeyChecking=no dist/*.tar.gz spotify-pypiserver@pypi.spotify.net:/var/lib/pypiserver/

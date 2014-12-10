#!/bin/bash

set -e

VIRTUAL_ENV=.venv

if [ -d "$VIRTUAL_ENV" ]; then
  rm -rf "$VIRTUAL_ENV"
fi

virtualenv $VIRTUAL_ENV

${VIRTUAL_ENV}/bin/pip install tox
${VIRTUAL_ENV}/bin/tox -- -v

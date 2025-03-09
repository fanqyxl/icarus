#!/bin/bash
SCRIPT_DIR=$(readlink -f "$(dirname "$0")")
if [ ! -e "${SCRIPT_DIR}/../.venv" ]; then
    python3 -m venv ${SCRIPT_DIR}/../.venv
fi
source ${SCRIPT_DIR}/.venv/bin/activate
pip3 install protobuf
bash
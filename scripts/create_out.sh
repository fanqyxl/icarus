#!/bin/bash
SCRIPT_DIR=$(dirname $0)
mkdir -p out/PKIMetadata/
if [ $# -lt 1 ]
then
    echo "Usage: $0 <root certificates...>"
    exit 1
fi

for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo "$file missing!"
        exit 1
    fi
done

echo "using chrome ${CHROME:="google-chrome"}"
if [ ! -d "$HOME/.config/$CHROME/PKIMetadata" ]
then
    echo "Opened chrome automatically, make sure you follow the README!"
    "$CHROME" chrome://components # &> /dev/null &
    exit 0  
fi
HIGHESTVERSIONAPPARENTLY=$(find  "$HOME/.config/$CHROME/PKIMetadata/" -maxdepth 1 -mindepth 1 -type d| head -n 1)
if [ -z ${HIGHESTVERSIONAPPARENTLY} ]; then
	echo "Failed to find PKIMetadata directory"
	exit 1
fi
mkdir -p original/PKIMetadata/9999
if [ "$HIGHESTVERSIONAPPARENTLY" != "" ]; then
    cp -rvf "$HIGHESTVERSIONAPPARENTLY"/. original/PKIMetadata/9999
else
    echo "Variable HIGHESTVERSIONAPPARENTLY returned empty, failing."
    exit 1
fi

rm -rvf original/PKIMetadata/9999/_metadata
rm -rvf original/PKIMetadata/9999/manifest.fingerprint

# Copy all directories, and will be modified by future calls
rm -rvf "${SCRIPT_DIR}"/../out
mkdir "${SCRIPT_DIR}"/../out
mkdir -p "${SCRIPT_DIR}"/../out/PKIMetadata/.
cp -rvf "${SCRIPT_DIR}"/../original/PKIMetadata/9999/. "${SCRIPT_DIR}"/../out/PKIMetadata
rm -rvf "${SCRIPT_DIR}"/../out/PKIMetadata/_metadata # verified contents not necessary
rm -rvf "${SCRIPT_DIR}/../out/PKIMetadata/"*.fingerprint
python3 ./src/root_store_gen/generate_new_pbs.py "${SCRIPT_DIR}/../original/PKIMetadata/9999/crs.pb" "$@" "${SCRIPT_DIR}/../out/PKIMetadata/crs.pb"
# Modify version in manifest

python3 <<EOF # Set version in manifest
import json
from pathlib import Path 
mjs = '${SCRIPT_DIR}/../original/PKIMetadata/9999/manifest.json'
mjs = Path(mjs)
newfile = Path('${SCRIPT_DIR}/../out/PKIMetadata/manifest.json')
dat = Path.read_text(mjs)
x = json.loads(dat)
x['version'] = "9999" 
print(json.dumps(x))
newfile.write_text(json.dumps(x))
EOF
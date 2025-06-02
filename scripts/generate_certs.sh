#!/bin/bash

SCRIPT_DIR=$(dirname "$0")
SCRIPT_DIR=${SCRIPT_DIR:-"."}

caFileList="myCA.pem myCA.key myCA.der ../myCA.der" 

cat <<EOF
CA & google.com key generator
written by kxtzownsu
(ty writable for helping me with openssl)
------------------------------------------
EOF

echo "Checking if CA keys exist.."
for file in $caFileList; do
    if [ ! -f "${SCRIPT_DIR}/$file" ]; then
        echo "CA keys are missing! Re-generating...."
        rm -rf $caFileList # just in case the user has key instead of pem or vice versa
        openssl genrsa -out "${SCRIPT_DIR}/myCA.key" 2048
        openssl req -x509 -new -nodes -key "${SCRIPT_DIR}/myCA.key" -sha256 -days 1826 -out "${SCRIPT_DIR}/myCA.pem" # generates a 5y cert
        openssl x509 -in "${SCRIPT_DIR}/myCA.pem" -out "${SCRIPT_DIR}/myCA.der" -outform DER
        if [ -f "${SCRIPT_DIR}/../modify.sh" ]; then #we check here if the previous dir is icarus, not a good check but it works :D
            cp "${SCRIPT_DIR}/myCA.der" "${SCRIPT_DIR}/../"
	fi
    fi
done

# generates new google.com keys
openssl genrsa -out "$SCRIPT_DIR/certs/google.com".key 4096
openssl req -new -key "$SCRIPT_DIR/certs/google.com".key -out "$SCRIPT_DIR/certs/in.csr" -subj "/C=US/ST=PRIVATE/L=PRIVATE/O=Success!/OU=Success/CN=$1"
cat > "$SCRIPT_DIR/certs/extfile" <<EOF

authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = *.google.com
EOF

openssl x509 -req -out "$SCRIPT_DIR/certs/google.com.pem" -CA "$SCRIPT_DIR/myCA.pem" -CAkey "$SCRIPT_DIR/myCA.key" -extfile "$SCRIPT_DIR/certs/extfile" -in "$SCRIPT_DIR/certs/in.csr"

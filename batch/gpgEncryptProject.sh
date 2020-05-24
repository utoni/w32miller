#!/bin/bash

set -e

GEN_PASSWD=0
if [ $(command -v date 2>&1) != "" -a \
	$(command -v sha256sum 2>&1) != "" -a \
	$(command -v base64 2>&1) != "" -a \
	$(command -v head 2>&1) != "" ]; then
		echo "$0: generating random passphrase"
		GEN_PASSWD=1
fi
#date +%s | sha256sum | base64 | head -c 40 ; echo


file="$(dirname $0)/../bin/w32miller.tar.gz"
mkdir -p "$(dirname ${file})"

git archive --prefix 'w32miller/' -o ${file} HEAD
if [ ${GEN_PASSWD} -eq 1 ]; then
	PASSPHRASE=$(date +%s | sha256sum | base64 | head -c 40)
	gpg --cipher-algo AES256 --yes --passphrase "${PASSPHRASE}" -a -c ${file}
else
	gpg --cipher-algo AES256 -a -c ${file}
fi

if [ $(command -v wipe 2>&1) != "" ]; then
	wipe -q -f ${file}
fi

echo "$0: generated armored gpg symmetric encrypted file: ${file}"
if [ ! -z "${PASSPHRASE}" ]; then
	echo "$0: PASSPHRASE: ${PASSPHRASE}"
fi

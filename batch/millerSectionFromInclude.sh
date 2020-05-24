#!/bin/sh

set -e

DEST="${1}"
DEFN="${2}"

if [ -z "${DEST}" -o -z "${DEFN}" ]; then
	echo "usage: $0 [INCLUDE-FILE] [INCLUDE-DEFINITION]" >&2
	false
fi

test -r ${DEST}
OUTPUT=$(cat ${DEST} | sed -n 's/#define\s\+'"${DEFN}"'\s\+"\(.*\)"$/\1/p')
echo -n ${OUTPUT}

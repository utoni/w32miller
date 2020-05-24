#!/bin/sh

set -e

TORHFILE=/var/lib/tor/hidden_service/hostname
DEST="$(dirname $0)/../deps/sysroot/${TORHFILE}"
DEFINE="HTTP_ONION"

if [ $# -ne 1 ]; then
    echo -e "usage: $0 [INCLUDE-FILE]\n\te.g. $0 $(realpath $(dirname $0)/../include/xor_strings.h)" >&2
    exit 1
fi

if [ -r "${DEST}" ]; then
    DEST=$(realpath "${DEST}")
    echo "$0: TOR Hidden Service hostname file: ${DEST} -> $(cat ${DEST})" >&2
    CURR_HOST=$(sed -n 's/#define\s*'${DEFINE}'\s*"\([a-zA-Z0-9]*\)"/\1/p' ${1})
    WANT_HOST=$(cat ${DEST} | cut -d'.' -f1)
    if [ "${CURR_HOST}" = "${WANT_HOST}" ]; then
        echo "$0: WARNING: ${DEFINE} is already the same: ${CURR_HOST} == ${WANT_HOST}" >&2
        exit 0
    fi
    sed -i 's/#define\s*'${DEFINE}'\s*"\([a-zA-Z0-9]*\)"/#define '${DEFINE}' "'$(cat ${DEST} | cut -d'.' -f1)'"/' ${1}
else
    echo "$0: WARNING: ${DEST} not FOUND !" >&2
fi

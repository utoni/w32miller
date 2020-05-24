#!/bin/bash

if [ $# -ne 2 ]; then
	printf "usage: %s [ORIG-DIR] [MODF-DIR]\n" "$0"
	exit 1
fi

set -e

NAME="$(basename $0)"
ORIG="$(basename $1)"
MODF="$(basename $2)"
CHDIR="$(dirname $1)"
TMPFILE="$(mktemp)"

cd ${CHDIR}

ret=0
diff -Naur ${ORIG} ${MODF} >${TMPFILE} || ret=$?
if [ $ret -ne 1 ]; then
	printf "%s: %s\n" "${NAME}" "No diffs found."
	exit 1
fi

ret=0
command -v filterdiff >/dev/null 2>/dev/null || ret=$?
if [ $ret -eq 0 ]; then
	filterdiff --remove-timestamps ${TMPFILE} >${MODF}.patch
else
	printf "%s: %s\n" "${NAME}" "Command \`filterdiff\` not found. Can not remove timestamps from patch"
	mv ${TMPFILE} ${MODF}.patch
fi

printf "%s: %s\n" "${NAME}" "Generated ${CHDIR}/${MODF}.patch"

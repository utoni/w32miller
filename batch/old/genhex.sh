#!/bin/bash

if [ -z "$1" ]; then
	DPATH="$(pwd)"
else
	DPATH="$1"
fi

echo "$0: generate *.hex files in $(ls ${DPATH})"
for file in $(ls ${DPATH}); do
	[ -d ${file} ] && continue
	FLEN=$((${#file}-4))
	FSUFFIX=${file:$FLEN:4}
	if [ "$FSUFFIX" != ".hex" ]; then
		xxd "${file}" > "${file}.hex"
	fi
done


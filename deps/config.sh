#!/bin/bash

MYPWD=$(realpath $(dirname ${BASH_SOURCE[0]}))
echo ">>> ${MYPWD}"

export targ="i686-w64-mingw32"
echo "target  = ${targ}"

export MY_SYS_ROOT="${MYPWD}/sysroot"
echo "sysroot = ${MY_SYS_ROOT}"

if [[ $- =~ e ]]; then
	echo '>>> disabled bash exit on non-zero (set -e)'
	BASH_EXITONFAIL=1
	set +e
else
	BASH_EXITONFAIL=0
fi

echo "${PATH}" | grep -qoE ":${MY_SYS_ROOT}"
if [ $? -ne 0 ]; then
	export PATH="${MY_SYS_ROOT}/bin:${MY_SYS_ROOT}/${targ}/bin:${PATH}"
fi
echo "PATH    = ${PATH}"

if [ $BASH_EXITONFAIL -eq 1 ]; then
	set -e
	unset BASH_EXITONFAIL
fi

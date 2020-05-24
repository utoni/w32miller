#!/bin/bash

set -e

OBJDUMP="$(dirname $0)/../deps/sysroot/bin/i686-w64-mingw32-objdump"
OBJDUMP_ARGS="-z -D"
TMPFILE="$(mktemp)"


if [ ! -x ${OBJDUMP} ]; then
	echo "$0: ${OBJDUMP} not found!"
	false
fi

if [ "x$1" != "x" -a "x$2" != "x" -a "x$3" != "x" -a "x$4" != "x" ]; then
	echo "$0: create tmpfile ${TMPFILE}"
	OBJECTFILE="${1}"
	OUTPUT="${2}"
	DEFINE="${3}"
        OBJDUMP_ARGS="${OBJDUMP_ARGS} -j ${4}"

	DO_APPEND=0
	if [ "x$5" != "x" ]; then
		echo "$5" | egrep -qi 'append.*=.*true' && DO_APPEND=1 || true
	fi

	if [ ! -r ${OBJECTFILE} ]; then
		echo "$0: ${OBJECTFILE} not found or not readable"
		false
	fi

	echo "$0: objdump command: \`${OBJDUMP} ${OBJDUMP_ARGS} ${OBJECTFILE}\`"
	export SIZE=0
	if [ ${DO_APPEND} -eq 1 ]; then
		echo "$0: APPENDING to ${OUTPUT}"
		cp ${OUTPUT} ${TMPFILE}
		echo >> ${TMPFILE}
		echo '#undef '"${DEFINE}" >> ${TMPFILE}
	else
		echo '#undef '"${DEFINE}" > ${TMPFILE}
	fi
	echo -n '#define '"${DEFINE}"' "' >> ${TMPFILE}
        # TODO: use objdump -s to show everything (-d shows only valid opcodes)
	for i in $(${OBJDUMP} ${OBJDUMP_ARGS} ${OBJECTFILE} |grep "^ " |cut -f2); do
		echo -n '\x'$i >>${TMPFILE}
		SIZE=$(expr $SIZE + 1)
	done
	if [ $SIZE -eq 0 ]; then
		echo "$0: Whoops! Something went wrong (SIZE=0)."
		echo "$0: Check output manually with: \`${OBJDUMP} ${OBJDUMP_ARGS} ${OBJECTFILE}\`"
		false
	fi
	echo '"' >>${TMPFILE}
	echo '#undef '"${DEFINE}"'_SIZE' >> ${TMPFILE}
	echo '#define '"${DEFINE}"'_SIZE '"${SIZE}" >> ${TMPFILE}
	mv ${TMPFILE} ${OUTPUT}
	echo "$0: moved ${TMPFILE} to ${OUTPUT}"
else
	echo "usage: $0 [OBJECT-FILE or STATIC-LIB] [OUTPUT-HEADER] [OUTPUT-DEFINE] [LOADER-SECTION] [DO-APPEND=[TRUE|FALSE]]"
	exit 1
fi

#!/bin/bash


if [ "x$1" = "x" ] || [ "x$2" = "x" ]; then
  echo "$0: [FILE1] [FILE2]"
  exit 1
fi

xxd "$1" > "$1.hex"
xxd "$2" > "$2.hex"
diff -du "$1.hex" "$2.hex" 2>&1 | less
rm -f "$1.hex" "$2.hex"

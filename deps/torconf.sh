#!/bin/bash

set -e


. "$(dirname $0)/config.sh"
TOR_CONF="${MY_SYS_ROOT}/etc/tor/torrc"


if [ ! -r ${TOR_CONF} ]; then
    if [ ! -r ${TOR_CONF}.sample ]; then
        echo "$0: Run $(dirname $0)/makedeps.sh first !" >&2
    fi

    set -x
    cp ${TOR_CONF}.sample ${TOR_CONF}

    sed -i 's/^\(#SOCKSPort\(.*\)address:port\(.*\)\)$/\1\nSOCKSPort 0/' ${TOR_CONF}
    sed -i 's/^#SOCKSPolicy reject \*/#SOCKSPolicy reject \*\nSOCKSPolicy accept 127.0.0.1\/32\nSOCKSPolicy reject \*/' ${TOR_CONF}
    sed -i 's/^#Log debug stderr/#Log debug stderr\nLog notice stderr/' ${TOR_CONF}
    sed -i 's/^#DataDirectory/DataDirectory/' ${TOR_CONF}
    sed -i 's/^#RunAsDaemon 1/RunAsDaemon 0/' ${TOR_CONF}
    sed -i 's/^#HiddenServiceDir\(.*\)\/hidden_service\/$/HiddenServiceDir\1\/hidden_service\/\nHiddenServicePort 80 127.0.0.1:8080/' ${TOR_CONF}

    mkdir -p "${MY_SYS_ROOT}/var/lib/tor"
else
    echo "$0: ${TOR_CONF} does already exist !" >&2
fi

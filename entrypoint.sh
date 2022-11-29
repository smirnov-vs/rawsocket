#!/bin/sh

set -eu

if ! iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2> /dev/null; then
    iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
fi

exec ./socket "$@"

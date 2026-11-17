#!/bin/sh
# Default to the foreground maintenance daemon; any arguments run as a
# subcommand instead (docker run image cert list, account register, ...).
set -eu

if [ "$#" -eq 0 ]; then
    exec aster-acme daemon run
fi

exec aster-acme "$@"

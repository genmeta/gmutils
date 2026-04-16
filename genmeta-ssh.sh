#!/usr/bin/env bash

# Check if parameter is -V
if [ "$#" -eq 1 ] && [ "$1" = -V ]
    then
    # Execute original ssh -V command
    ssh -V
else
    # Call genmeta-ssh and pass all arguments
    # If genmeta ssh fails, fall back to traditional ssh for compatibility
    genmeta ssh "$@" || {
        echo "genmeta ssh process failed, falling back to regular ssh..." >&2
        ssh "$@"
    }
fi

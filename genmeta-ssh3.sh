#!/usr/bin/env bash

# Check if parameter is -V
if [ "$#" -eq 1 ] && [ "$1" = -V ]
    then
    # Execute original ssh -V command
    ssh -V
else
    # Call genmeta-ssh3 and pass all arguments
    # If genmeta ssh3 fails, fall back to traditional ssh for compatibility
    genmeta ssh3 "$@" || {
        echo "Custom ssh process failed, falling back to regular ssh..." >&2
        ssh "$@"
    }
fi

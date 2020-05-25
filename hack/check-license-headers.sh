#!/bin/bash

# Idea and initial code taken from:
# https://github.com/SerenityOS/serenity/blob/50265858abfc562297c62645e1ca96f16c46aad1/Meta/check-license-headers.sh
# Copyright (c) 2020 the SerenityOS developers.
#
# The code in this file is licensed under the 2-clause BSD license.

script_path=$(cd -P -- "$(dirname -- "$0")" && pwd -P)

# We check if the file starts with "// Copyright". If it doesn't, it is
# classified as an error.
PATTERN=$'^// Copyright'
ERRORS=()

while IFS= read -r f; do
    if [[ ! $(cat "$f") =~ $PATTERN ]]; then
        ERRORS+=("$f")
    fi
done < <(git ls-files -- \
'*.rs' \
)

if (( ${#ERRORS[@]} )); then
    echo "Files missing license headers: ${ERRORS[*]}"
    exit 1
fi

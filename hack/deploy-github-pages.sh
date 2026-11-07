#!/bin/bash

set -e

: "${COMMIT_MESSAGE:?"COMMIT_MESSAGE needs to be non-empty"}"

function git_add {
    echo "📐 Adding all new/changed/removed files"
    git add .
}

function git_commit {
    echo "📦 Creating commit"
    git \
        -c "user.name=GitHub" \
        -c "user.email=noreply@github.com" \
        commit \
        --quiet \
        --author="github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>" \
        --message "${COMMIT_MESSAGE}"
}

function git_push {
    git push
}

git_add
if ! git diff --cached --quiet; then
    git_commit
    echo "📃 Pushing changes"
    git_push
fi
echo "🎉 Successfully deployed to GitHub pages!"

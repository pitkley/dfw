#!/bin/bash

: "${COMMIT_MESSAGE:?"COMMIT_MESSAGE needs to be non-empty"}"

function git_add {
    echo "📐 Adding all new/changed/removed files"
    git add .
}

function git_commit {
    echo "📦 Creating commit"
    local status=0
    git \
        -c "user.name=GitHub" \
        -c "user.email=noreply@github.com" \
            commit \
            --quiet \
            --author="github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>" \
            --message "${COMMIT_MESSAGE}" \
        || status=$?
    echo "status: $status"
    case "$status" in
    0)
        echo "return 0"
        return 0
        ;;
    1)
        # Couldn't create a commit because it would have been empty.
        echo "⚠️ No commit required"
        return 1
        ;;
    *)
        echo "exit 1!"
        # A different error has occurred, exit!
        exit 1
        ;;
    esac
}

function git_push {
    git push
}

git_add
if git_commit; then
    echo "📃 Pushing changes"
    git_push
fi
echo "🎉 Successfully deployed to GitHub pages!"

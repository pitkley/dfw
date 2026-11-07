# Releasing

Use `cargo release` to prepare a release commit on a branch.
Merge that commit through a pull request, then publish a signed tag.

This ensures the version bump and changelog use the same review process with successful CI runs as other changes to `main`.

## Prepare the release PR

Choose the bump using the [version policy](README.md#versionbumppolicy).

| Change | Bump | Example from 1.3.0 |
| --- | --- | --- |
| Compatible fixes and dependency updates | `patch` | `1.3.1` |
| Compatible features or a higher minimum Rust version | `minor` | `1.4.0` |
| Breaking changes | `major` | `2.0.0` |

For a release candidate, pass an explicit version such as `1.3.1-rc.1` to choose the target version.
Use `release` to promote a prerelease version.

From a clean checkout, create the release branch from current `main` and preview the bump.
Add `--execute` once the preview looks right.

```sh
git fetch origin main
git switch -c release/1.3.1 origin/main
cargo release patch --no-publish --no-tag --no-push
cargo release patch --no-publish --no-tag --no-push --execute
```

Review the signed release commit, including the changelog and versioned links.
Then open the PR and merge it after CI passes.

```sh
git push -u origin release/1.3.1
gh pr create --base main --fill
```

## Tag and publish

Sign the version tag on the commit that the release PR landed on `main`.
Use the exact commit SHA from the merged PR so later commits on `main` cannot accidentally enter the release.
Replace `RELEASE_MERGE_SHA` with that SHA.

```sh
git fetch origin main
git tag -s 1.3.1 RELEASE_MERGE_SHA -m 'Release DFW 1.3.1'
git push origin refs/tags/1.3.1
```

The tag triggers the Docker images, versioned Pages docs, and a draft GitHub release with binaries and checksums.
After the jobs pass, review the draft and publish it on GitHub.
For a stable release, publish the crate from the tagged checkout.

```sh
git switch --detach 1.3.1
cargo publish --locked
```

## Set up GPG

* Install GnuPG
* Import the private-key:

    ```
    gpg --import private.key
    ```

* Verify GnuPG is working using clearsign:

    ```
    echo "test" | gpg --clearsign
    ```

    If an error like `gpg: signing failed: Inappropriate ioctl for device` pops up, the following should help:

    ```
    # Bash-like shells:
    export GPG_TTY=$(tty)
    # Fish:
    set -x GPG_TTY (tty)
    ```

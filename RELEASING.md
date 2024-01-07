# Releasing

* Releasing a release-candidate:

    ```
    cargo release --no-publish rc
    ```

* Releasing a full version:

    ```
    cargo release
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

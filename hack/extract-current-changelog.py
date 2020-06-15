#!/usr/bin/env python3

from enum import auto, Enum
import sys


class State(Enum):
    Initial = auto()
    BeforeYielding = auto()
    Yielding = auto()
    End = auto()


def get_current_changelog(changelog_path):
    with open(changelog_path, 'r') as fh:
        state = State.Initial
        for line in fh.readlines():
            line = line.rstrip()
            if state == State.End:
                break
            elif state == State.Initial:
                if line.startswith("## "):
                    state = State.BeforeYielding
            elif state == state.BeforeYielding:
                if line.strip():
                    state = State.Yielding
                    yield line
            elif state == state.Yielding:
                if line.startswith("## "):
                    state = State.End
                else:
                    yield line


if __name__ == '__main__':
    try:
        changelog_path = sys.argv[1]
    except:
        print("USAGE: extract-current-changelog.py <CHANGELOG_PATH>", file=sys.stderr)
        exit(1)
    for line in get_current_changelog(changelog_path):
        print(line)

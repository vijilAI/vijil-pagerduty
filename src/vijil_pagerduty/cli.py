"""vijil-pagerduty: `dome` and `diamond` read Phoenix (see bridge); `test` sends sample events (see reviewer)."""

import sys

from vijil_pagerduty import bridge, reviewer


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["test"]:
        return reviewer.main(argv[1:])
    return bridge.main(argv)


if __name__ == "__main__":
    sys.exit(main())

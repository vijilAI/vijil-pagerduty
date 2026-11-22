"""vijil-pagerduty: `test` sends sample Vijil events to a PagerDuty integration (see reviewer).

Vijil Console sends the real events itself; this package exists so a PagerDuty user or reviewer
can check an Integration Key without a Vijil account.
"""

import sys

from vijil_pagerduty import reviewer


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["test"]:
        return reviewer.main(argv[1:])
    print("usage: vijil-pagerduty test [--action trigger|acknowledge|resolve] [--dry-run]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

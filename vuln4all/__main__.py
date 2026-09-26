"""让 `python3 -m vuln4all …` 能跑起来。"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

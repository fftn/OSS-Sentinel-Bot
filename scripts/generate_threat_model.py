#!/usr/bin/env python3
from oss_sentinel.cli import main
import sys


if __name__ == "__main__":
    raise SystemExit(main(["baseline", *sys.argv[1:]]))


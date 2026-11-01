#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ipcheck.py — 入口（实现已拆分到 ipcheck_lib 包）。

保持向后兼容：所有 `ipcheck.<name>` 仍可用（sources/scoring/render/env/csvio/cli 星导出）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipcheck_lib.constants import *  # noqa: F401,F403
from ipcheck_lib.http import *  # noqa: F401,F403
from ipcheck_lib.sources import *  # noqa: F401,F403
from ipcheck_lib.scoring import *  # noqa: F401,F403
from ipcheck_lib.render import *  # noqa: F401,F403
from ipcheck_lib.env import *  # noqa: F401,F403
from ipcheck_lib.csvio import *  # noqa: F401,F403
from ipcheck_lib.cli import *  # noqa: F401,F403

if __name__ == "__main__":
    sys.exit(main())

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package

# Originally proposed by kidrek:
# https://github.com/cuckoobox/cuckoo/pull/136

class VBS(Package):
    """VBS analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .vbs extension force it
        # and rename it. This is needed for wscript to execute correctly.
        if ext != ".vbs":
            new_path = path + ".vbs"
            os.rename(path, new_path)
            path = new_path

        return self.execute(wscript, "\"%s\"" % path, path)

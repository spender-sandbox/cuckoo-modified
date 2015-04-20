# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class SWF(Package):
    """Shockwave Flash analysis package.
        Download a version of standalone flash from adobe and 
        place in bin/ as flashplayer.exe to use
    """

    def start(self, path):
        return self.execute("bin/flashplayer.exe", path, path)

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process

class SWF(Package):
    """Shockwave Flash analysis package.
        Download a version of standalone flash from adobe and 
        place in bin/ as flashplayer.exe to use
    """

    def start(self, path):
        p = Process()
        free = self.options.get("free")
        dll = self.options.get("dll")
        p.execute(path="bin/flashplayer.exe", args=path, suspended=True)
        p.inject(dll, path)
        p.resume()
        if free:
            return None
        return p.pid

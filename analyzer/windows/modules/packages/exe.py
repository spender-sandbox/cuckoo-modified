# Copyright (C) 2010-2014 Cuckoo Foundation, Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package

class Exe(Package):
    """EXE analysis package."""

    def start(self, path):
        args = self.options.get("arguments")
        appdata = self.options.get("appdata")
        if appdata:
            # run the executable from the APPDATA directory, required for some malware
            basepath = os.getenv('APPDATA')
            newpath = os.path.join(basepath, os.path.basename(path))
            shutil.copy(path, newpath)
            path = newpath
        return self.execute(path, args)

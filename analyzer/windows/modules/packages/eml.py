# Copyright (C) 2010-2015 Cuckoo Foundation., Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class EML(Package):
    """Outlook EML analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office11", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office12", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office14", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office15", "OUTLOOK.EXE"),
    ]

    def start(self, path):
        outlook = self.get_path("Microsoft Office Outlook")
        return self.execute(outlook, "/eml \"%s\"" % path, path)

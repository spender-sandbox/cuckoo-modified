# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File

class Dropped(Processing):
    """Dropped files analysis."""

    def run(self):
        """Run analysis.
        @return: list of dropped files with related information.
        """
        self.key = "dropped"
        dropped_files = []

        for dir_name, dir_names, file_names in os.walk(self.dropped_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                if file_name.endswith("_info.txt") and not os.path.exists(file_path + "_info.txt"):
                    continue
                guest_paths = [line.strip() for line in open(file_path + "_info.txt")]

                file_info = File(file_path=file_path,guest_paths=guest_paths).get_all()
                dropped_files.append(file_info)

        return dropped_files

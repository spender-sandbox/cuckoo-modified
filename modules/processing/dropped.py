# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable

class Dropped(Processing):
    """Dropped files analysis."""

    def run(self):
        """Run analysis.
        @return: list of dropped files with related information.
        """
        self.key = "dropped"
        dropped_files = []
        buf = self.options.get("buffer", 8192)

        for dir_name, dir_names, file_names in os.walk(self.dropped_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                if file_name.endswith("_info.txt") and not os.path.exists(file_path + "_info.txt"):
                    continue
                guest_paths = [line.strip() for line in open(file_path + "_info.txt")]

                file_info = File(file_path=file_path,guest_paths=guest_paths).get_all()
                # Used by ElasticSearch to find the file on disk
                # since they are in random generated directories
                if Config("reporting").get("elasticsearchdb").get("enabled"):
                    file_info["dropdir"] = file_path.split("/")[-2]
                texttypes = [
                    "ASCII",
                    "Windows Registry text",
                    "XML document text",
                    "Unicode text",
                ]
                readit = False
                for texttype in texttypes:
                    if texttype in file_info["type"]:
                        readit = True
                        break
                if readit:
                    with open(file_info["path"], "r") as drop_open:
                        filedata = drop_open.read(buf + 1)
                    if len(filedata) > buf:
                        file_info["data"] = convert_to_printable(filedata[:buf] + " <truncated>")
                    else:
                        file_info["data"] = convert_to_printable(filedata)

                dropped_files.append(file_info)

        return dropped_files

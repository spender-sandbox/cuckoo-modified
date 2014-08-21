# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class FilteredEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, dict):
                args = obj["arguments"]
                if args:
                    newdict = args.copy()
                    for arg in newdict:
                        del arg["raw_value"]
                    return json.JSONEncoder.default(self, newdict)
            else:
                return json.JSONEncoder.default(self, obj)

class JsonDump(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
            path = os.path.join(self.reports_path, "report.json")
            report = codecs.open(path, "w", "utf-8")
            json.dump(results, report, cls=FilteredEncoder, sort_keys=False, indent=4)
            report.close()
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)

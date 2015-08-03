# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    from weasyprint import HTML
    HAVE_WEASYPRINT = True
except ImportError:
    HAVE_WEASYPRINT = False


class ReportPDF(Report):
    """Stores report in PDF format."""
    # ensure we run after the summary HTML report
    order = 10

    def run(self, results):
        if not HAVE_WEASYPRINT:
            raise CuckooReportError("Failed to generate PDF report: "
                                    "Weasyprint Python library is not installed")

        if not os.path.isfile(os.path.join(self.reports_path, "summary-report.html")):
            raise CuckooReportError("Unable to open summary HTML report to convert to PDF: "
                                    "Ensure reporthtmlsummary is enabled in reporting.conf")
        
        logger = logging.getLogger("weasyprint")
        logger.handlers = []
        logger.setLevel(logging.ERROR)

        HTML(os.path.join(self.reports_path, "summary-report.html")).write_pdf(os.path.join(self.reports_path, "report.pdf"))

        return True

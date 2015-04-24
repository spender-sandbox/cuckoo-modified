# Copyright (C) 2014-2015 Will Metcalf william.metcalf@gmail.com 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import logging
import pprint

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

class ReSubmitExtractedEXE(Report):
    def run(self, results):
        self.noinject = self.options.get("noinject", False)
        self.resublimit = int(self.options.get("resublimit",5))
        filesdict = {}
        self.task_options_stack = []
        self.task_options = None
        self.task_custom = None
        self.resubcnt = 0
        report = dict(results)

        if report["info"].has_key("options") and report["info"]["options"].has_key("resubmitjob") and report["info"]["options"]["resubmitjob"]:
            return
        else:
           self.task_options_stack.append("resubmitjob=true")
        if self.noinject:
            self.task_options_stack.append("free=true")
         
        if self.task_options_stack:
            self.task_options=','.join(self.task_options_stack)

        report = dict(results)
        for dropped in report["dropped"]:
            if self.resubcnt >= self.resublimit:
                break
            if os.path.isfile(dropped["path"]):
                if ("PE32" in dropped["type"] or "MS-DOS" in dropped["type"]) and "DLL" not in dropped["type"]:
                    if not filesdict.has_key(dropped['sha256']):
                        filesdict[dropped['sha256']] = dropped['path']
                        self.resubcnt = self.resubcnt + 1
            
        if report.has_key("suricata") and report["suricata"]:
            if report["suricata"].has_key("files") and report["suricata"]["files"]:
                for suricata_file_e in results["suricata"]["files"]:
                    if self.resubcnt >= self.resublimit:
                        break
                    if suricata_file_e.has_key("file_info"):
                        tmp_suricata_file_d = dict(suricata_file_e)
                        if os.path.isfile(suricata_file_e["file_info"]["path"]):
                            ftype = suricata_file_e["file_info"]["type"]
                            if ("PE32" in ftype or "MS-DOS" in ftype) and "DLL" not in ftype:
                                if not filesdict.has_key(suricata_file_e["file_info"]["sha256"]):
                                    filesdict[suricata_file_e["file_info"]["sha256"]] = suricata_file_e["file_info"]["path"]
                                    self.resubcnt = self.resubcnt + 1

        db = Database()

        for e in filesdict:
            if not File(filesdict[e]).get_size():
                continue
            if not db.find_sample(sha256=e) is None:
                continue

            self.task_custom="Parent_Task_ID:%s" % report["info"]["id"]
            if report["info"].has_key("custom") and report["info"]["custom"]:
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom,report["info"]["custom"])
            task_id = db.add_path(file_path=filesdict[e],
                                  package='exe',
                                  timeout=200,
                                  options=self.task_options,
                                  priority=1,
                                  machine=None,
                                  platform=None,
                                  custom=self.task_custom,
                                  memory=False,
                                  enforce_timeout=False,
                                  clock=None,
                                  tags=None)

            if task_id:
                log.info(u"Resubmitexe file \"{0}\" added as task with ID {1}".format(filesdict[e], task_id))
            else:
                log.warn("Error adding resubmitexe task to database")
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""

import os
import json
import logging
import threading
from collections import deque
from datetime import datetime
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT

PYMISP = False
try:
    from pymisp import PyMISP
    PYMISP = True
except ImportError:
    pass

log = logging.getLogger(__name__)

class MISP(Report):
    """MISP Analyzer."""

    order = 1

    def misper_thread(self, url):
        while self.iocs:
            ioc = self.iocs.pop()
            try:
                response = self.misp.search_all(ioc)
                if not response or not response.get("response", {}):
                    continue
                self.lock.acquire()
                try:
                    for res in response.get("response", {}):
                        event = res.get("Event", {})

                        self.misp_full_report.setdefault(ioc, list())
                        self.misp_full_report[ioc].append(event)

                        eid = event.get("id", 0)

                        if eid in self.misper and ioc not in self.misper[eid]["iocs"]:
                            self.misper[eid]["iocs"].append(ioc)
                        else:
                            tmp_misp = dict()
                            tmp_misp.setdefault(eid, dict())
                            date = event.get("date", "")
                            if "iocs" not in tmp_misp[eid]:
                                tmp_misp[eid].setdefault("iocs", list())
                            tmp_misp[eid]["iocs"].append(ioc)
                            tmp_misp[eid].setdefault("eid", eid)
                            tmp_misp[eid].setdefault("url", url+"events/view/")
                            tmp_misp[eid].setdefault("date", date)
                            tmp_misp[eid].setdefault("level", event.get("threat_level_id",""))
                            tmp_misp[eid].setdefault("info", event.get("info", "").strip())
                            self.misper.update(tmp_misp)
                finally:
                    self.lock.release()
            except Exception as e:
                log.error(e)

    def run(self, results):
        """Run analysis.
        @return: MISP results dict.
        """

        if not PYMISP:
            log.error("pyMISP dependency is missing.")
            return

        url = self.options.get("url", "")
        apikey = self.options.get("apikey", "")

        if not url or not apikey:
            log.error("MISP URL or API key not configured.")
            return

        threads = self.options.get("threads", "")
        if not threads:
            threads = 5

        whitelist = list()
        self.iocs = deque()
        self.misper = dict()
        threads_list = list()
        self.misp_full_report = dict()
        self.lock = threading.Lock()

        try:
            # load whitelist if exists
            if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
                whitelist = Config("misp").whitelist.whitelist
                if whitelist:
                    whitelist = [ioc.strip() for ioc in whitelist.split(",")]

            self.misp = PyMISP(url, apikey, False, "json")

            for drop in results.get("dropped", []):
                if drop.get("md5", "") and drop["md5"] not in self.iocs and drop["md5"] not in whitelist:
                    self.iocs.append(drop["md5"])

            if results.get("target", {}).get("file", {}).get("md5", "") and results["target"]["file"]["md5"] not in whitelist:
                self.iocs.append(results["target"]["file"]["md5"])
            for block in results.get("network", {}).get("hosts", []):
                if block.get("ip", "") and block["ip"] not in self.iocs and block["ip"] not in whitelist:
                    self.iocs.append(block["ip"])
                if block.get("hostname", "") and block["hostname"] not in self.iocs and block["hostname"] not in whitelist:
                    self.iocs.append(block["hostname"])

            if not self.iocs:
                return

            for thread_id in xrange(int(threads)):
                thread = threading.Thread(target=self.misper_thread, args=(url,))
                thread.daemon = True
                thread.start()

                threads_list.append(thread)

            for thread in threads_list:
                thread.join()

            if self.misper:
                results["misp"] = sorted(self.misper.values(), key=lambda x: datetime.strptime(x["date"], "%Y-%m-%d"), reverse=True)
                misp_report_path = os.path.join(self.reports_path, "misp.json")
                full_report = open(misp_report_path, "wb")
                full_report.write(json.dumps(self.misp_full_report))
                full_report.close()
        except Exception as e:
            log.error("Failed to generate JSON report: %s" % e)

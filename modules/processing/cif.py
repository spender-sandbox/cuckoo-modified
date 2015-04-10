# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com), Cuckoo Foundation
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import requests
import hashlib
import urllib

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

class CIF(Processing):
    """Queries IP/domain results from CIF server"""
    order = 999

    def getbool(self,s):
        if isinstance(s,bool):
            rtn = s
        else:
            try:
                rtn = s.lower() in ("yes", "true", "1")
            except:
                rtn = False
        return rtn

    def run(self):
        """Runs CIF processing
        @return: full CIF report.
        """
        self.key = "cif"
        cif = []
        resources = []

        key = self.options.get("key", None)
        timeout = self.options.get("timeout", 60)
        url = self.options.get("url", None)
        confidence = self.options.get("confidence", 85)
        nolog = self.getbool(self.options.get("nolog", True))
        per_lookup_limit = self.options.get("per_lookup_limit", 20)
        per_analysis_limit = self.options.get("per_analysis_limit", 200)

        if not baseurl:
            raise CuckooProcessingError("CIF URL not configured, skip")

        if not key:
            raise CuckooProcessingError("CIF API key not configured, skip")

        # add IOC from submission
        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("File {0} not found, skipping it".format(self.file_path))

            resource = File(self.file_path).get_md5()
        elif self.task["category"] == "url":
            # normalize URL according to CIF specification
            suburl = self.task["target"]
            uri = suburl
            if ":" in suburl:
                uri = suburl[suburl.index(':')+1:]
            uri = uri.strip("/")
            query = urllib.quote(uri.encode('utf8')).lower()
            resource = hashlib.sha1(query).hexdigest()
        else:
            # Not supported type, exit.
            return cif

        # add IOCs from previous network processing
        if "network" in self.results:
            hosts = self.results["network"].get("hosts")
            if hosts:
                resources.extend(hosts)
            domains = self.results["network"].get("domains")
            if domains:
                resources.extend(domains)

        # add IOCs from dropped files
        if "dropped" in self.results:
            for dropped in self.results["dropped"]:
                if os.path.isfile(dropped["path"]):
                    if "PE32" in dropped["type"] or "MS-DOS" in dropped["type"]:
                        resources.append(File(dropped["path"]).get_md5())

        headers = {
            "User-Agent" : "Mozilla Cuckoo"
        }

        for res in resources[:per_analysis_limit]:
            data = {"query": res, "apikey": key, "nolog" : nolog, "confidence" : confidence, "limit" : per_lookup_limit, "fmt" : "json", }

            try:
                r = requests.get(url, headers=headers, params=data, verify=True, timeout=int(timeout))
                response_data = r.content
            except requests.exceptions.RequestException as e:
                raise CuckooProcessingError("Unable to complete connection to CIF server: {0}".format(e))

            try:
                resplines = [i.strip() for i in response_data.splitlines()]
                ciftmp = [json.loads(i) for i in resplines]
                cif.extend(ciftmp)
            except ValueError as e:
                raise CuckooProcessingError("Unable to convert response to JSON: {0}".format(e))

        return cif

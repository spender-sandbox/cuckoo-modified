# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Feed

class AbuseCH_SSL(Feed):
    name = "Bad_SSL_Certs"

    def __init__(self):
        self.downloadurl = "https://sslbl.abuse.ch/downloads/ssl_extended.csv"
        self.feedname = "abuse_ch_ssl"
        self.frequency = 6

    def modify(self):
        newdata = ""
        seen = set()
        data = self.downloaddata
        for line in data.splitlines():
            item = line.split(",")
            if len(item) != 6:
                pass
            else:
                # Remove header column and deduplicate data
                if "SSL" not in item[4] and item[4] not in seen:
                    newdata += ",".join(item[4:6]) + "\r\n"
                seen.add(item[4])
        self.data = newdata

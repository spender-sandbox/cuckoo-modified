# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.constants import CUCKOO_ROOT

class ProcessMemory(Processing):
    """Analyze process memory dumps."""

    def parse_dump(self, dmp_path):
        f = open(dmp_path, "rb")
        address_space = []
        while True:
            data = f.read(24)
            if data == '':
                break
            alloc = dict()
            addr,size,mem_state,mem_type,mem_prot = struct.unpack("QIIII", data)
            offset = f.tell()
            alloc["start"] = addr
            alloc["end"] = addr + size
            alloc["size"] = size
            alloc["prot"] = mem_prot
            alloc["state"] = mem_state
            alloc["type"] = mem_type
            alloc["PE"] = False
            if f.read(2) == "MZ":
                alloc["PE"] = True
            f.seek(size-2, 1)
            address_space.append(alloc)
        return address_space

    def run(self):
        """Run analysis.
        @return: structured results.
        """
        self.key = "procmemory"
        results = []

        if os.path.exists(self.pmemory_path):
            for dmp in os.listdir(self.pmemory_path):
                dmp_path = os.path.join(self.pmemory_path, dmp)
                dmp_file = File(dmp_path)

                proc = dict(
                    file=dmp_path,
                    pid=os.path.splitext(os.path.basename(dmp_path))[0],
                    yara=dmp_file.get_yara(os.path.join(CUCKOO_ROOT, "data", "yara", "index_memory.yar")),
                    address_space=parse_dump(dmp_path)
                )

                results.append(proc)

        return results

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import struct

PAGE_NOACCESS           = 0x00000001
PAGE_READONLY           = 0x00000002
PAGE_READWRITE          = 0x00000004
PAGE_WRITECOPY          = 0x00000008
PAGE_EXECUTE            = 0x00000010
PAGE_EXECUTE_READ       = 0x00000020
PAGE_EXECUTE_READWRITE  = 0x00000040
PAGE_EXECUTE_WRITECOPY  = 0x00000080
PAGE_GUARD              = 0x00000100
PAGE_NOCACHE            = 0x00000200
PAGE_WRITECOMBINE       = 0x00000400

protmap = {
    PAGE_NOACCESS : "NOACCESS",
    PAGE_READONLY : "R",
    PAGE_READWRITE : "RW",
    PAGE_WRITECOPY : "RWC",
    PAGE_EXECUTE : "X",
    PAGE_EXECUTE_READ : "RX",
    PAGE_EXECUTE_READWRITE : "RWX",
    PAGE_EXECUTE_WRITECOPY : "RWXC",
}

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.constants import CUCKOO_ROOT

class ProcessMemory(Processing):
    """Analyze process memory dumps."""
    order = 10

    def prot_to_str(self, prot):
        if prot & PAGE_GUARD:
            return "G"
        prot &= 0xff
        return protmap[prot]

    def coalesce_chunks(self, chunklist):
        low = chunklist[0]["start"]
        high = chunklist[-1]["end"]
        prot = chunklist[0]["prot"]
        PE = chunklist[0]["PE"]
        for chunk in chunklist:
            if chunk["prot"] != prot:
                prot = "Mixed"
        return { "start" : low, "end" : high, "size" : "0x%x" % (int(high, 16) - int(low, 16)), "prot" : prot, "PE" : PE, "chunks" : chunklist }

    def parse_dump(self, dmp_path):
        f = open(dmp_path, "rb")
        address_space = []
        curchunk = []
        lastend = 0
        while True:
            data = f.read(24)
            if data == '':
                break
            alloc = dict()
            addr,size,mem_state,mem_type,mem_prot = struct.unpack("QIIII", data)
            offset = f.tell()
            if addr != lastend and len(curchunk):
                address_space.append(self.coalesce_chunks(curchunk))
                curchunk = []
            lastend = addr + size
            alloc["start"] = "0x%.08x" % addr
            alloc["end"] = "0x%.08x" % (addr + size)
            alloc["size"] = "0x%x" % size
            alloc["prot"] = self.prot_to_str(mem_prot)
            alloc["state"] = mem_state
            alloc["type"] = mem_type
            alloc["offset"] = offset
            alloc["PE"] = False
            if f.read(2) == "MZ":
                alloc["PE"] = True
            f.seek(size-2, 1)
            curchunk.append(alloc)
        if len(curchunk):
            address_space.append(self.coalesce_chunks(curchunk))

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
                process_name = ""
                process_path = ""
                process_id = int(os.path.splitext(os.path.basename(dmp_path))[0])
                if "behavior" in self.results and "processes" in self.results["behavior"]:
                    for process in self.results["behavior"]["processes"]:
                        if process_id == process["process_id"]:
                            process_name = process["process_name"]
                            process_path = process["module_path"]
                proc = dict(
                    file=dmp_path,
                    pid=process_id,
                    name=process_name,
                    path=process_path,
                    yara=dmp_file.get_yara(os.path.join(CUCKOO_ROOT, "data", "yara", "index_memory.yar")),
                    address_space=self.parse_dump(dmp_path)
                )

                # Deduplicate configs
                if proc["yara"]:
                    for match in proc["yara"]:
                        # Dyre
                        if match["name"] == "DyreCfgInjectsList":
                            output = list()
                            buf = ""
                            recline = False
                            for ystring in match["strings"]:
                                for line in ystring.splitlines():
                                    if line.startswith("<litem>"):
                                        buf = ""
                                        recline = True
                                    if recline:
                                        buf += line.strip() + "\n"
                                    if line.startswith("</litem>"):
                                        recline = False
                                        if buf not in output:
                                            output.append(buf)

                            match["strings"] = ["".join(output)]
                            match["meta"]["description"] += " (Observed %d unique inject elements)" % len(output)

                        elif match["name"] == "DyreCfgRedirectList":
                            output = list()
                            buf = ""
                            recline = False
                            for ystring in match["strings"]:
                                for line in ystring.splitlines():
                                    if line.startswith("<rpcgroup>"):
                                        buf = ""
                                        recline = True
                                    if recline:
                                        buf += line.strip() + "\n"
                                    if line.startswith("</rpcgroup>"):
                                        recline = False
                                        if buf not in output:
                                            output.append(buf)

                            match["strings"] = ["".join(output)]
                            match["meta"]["description"] += " (Observed %d unique redirect elements)" % len(output)

                        # DarkComet
                        elif match["name"] == "DarkCometConfig":
                            output = list()
                            recline = False
                            for ystring in match["strings"]:
                                for line in ystring.splitlines():
                                    if line.startswith("#BEGIN DARKCOMET"):
                                        buf = ""
                                        recline = True
                                    if recline:
                                        buf += line.strip() + "\n"
                                    if line.startswith("#EOF DARKCOMET"):
                                        recline = False
                                        if buf not in output:
                                            output.append(buf)

                            match["strings"] = ["".join(output)]

                results.append(proc)

        return results

# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import hashlib
import urllib

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

def sanitize_file(filename):
    normals = filename.lower().replace('\\', ' ').replace('.', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals]
    return ' '.join(hashed_components)

def sanitize_reg(keyname):
    normals = keyname.lower().replace('\\', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals]
    return ' '.join(hashed_components)

def sanitize_cmd(cmd):
    normals = cmd.lower().replace('"', '').replace('\\', ' ').replace('.', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals]
    return ' '.join(hashed_components)

def sanitize_generic(value):
    return hashlib.md5(value.lower()).hexdigest()[:8]

def sanitize_domain(domain):
    components = domain.lower().split('.')
    hashed_components = [hashlib.md5(comp).hexdigest()[:8] for comp in components]
    return ' '.join(hashed_components)

def sanitize_ip(ipaddr):
    components = ipaddr.split('.')
    class_c = components[:3]
    return hashlib.md5('.'.join(class_c)).hexdigest()[:8] + " " + hashlib.md5(ipaddr).hexdigest()[:8]

def sanitize_url(url):
    # normalize URL according to CIF specification
    uri = url
    if ":" in url:
        uri = url[url.index(':')+1:]
    uri = uri.strip("/")
    quoted = urllib.quote(uri.encode('utf8')).lower()
    return hashlib.md5(quoted).hexdigest()[:8]

def mist_convert(results):
    """ Performs conversion of analysis results to MIST format """
    lines = []
    if "behavior" in results and "summary" in results["behavior"]:
        for entry in results["behavior"]["summary"]["files"]:
            lines.append("file access|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["write_files"]:
            lines.append("file write|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["delete_files"]:
            lines.append("file delete|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["read_files"]:
            lines.append("file read|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["keys"]:
            lines.append("reg access|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["read_keys"]:
            lines.append("reg read|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["write_keys"]:
            lines.append("reg write|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["delete_keys"]:
            lines.append("reg delete|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["executed_commands"]:
            lines.append("cmd exec|" + sanitize_cmd(entry))
        for entry in results["behavior"]["summary"]["mutexes"]:
            lines.append("mutex access|" + sanitize_generic(entry))
        for entry in results["behavior"]["summary"]["created_services"]:
            lines.append("service create|" + sanitize_generic(entry))
        for entry in results["behavior"]["summary"]["started_services"]:
            lines.append("service start|" + sanitize_generic(entry))
    if "signatures" in results:
        for entry in results["signatures"]:
            sigline = "sig " + entry["name"] + "|"
            if entry["data"]:
                for res in entry["data"]:
                    for key, value in res.items():
                        lines.append(sigline + sanitize_generic(value))
            else:
                lines.append(sigline)
    if "network" in results:
        hosts = results["network"].get("hosts")
        if hosts:
            for host in hosts:
                lines.append("net con|" + sanitize_generic(host["country_name"]) + " " + sanitize_ip(host["ip"]))
        domains = results["network"].get("domains")
        if domains:
            for domain in domains:
                lines.append("net dns|" + sanitize_domain(domain["domain"]))
        httpreqs = results["network"].get("http")
        if httpreqs:
            for req in httpreqs:
                lines.append("net http|" + sanitize_url(req["uri"]))

    if "dropped" in results:
        for dropped in results["dropped"]:
            lines.append("file drop|" + "%08x" % (int(dropped["size"]) & 0xfffffc00) + " " + sanitize_generic(dropped["type"]))

    if "static" in results:
        if "digital_signers" in results["static"]:
            for info in results["static"]["digital_signers"]:
                lines.append("pe sign|" + sanitize_generic(info["cn"]) + " " + sanitize_generic(info["md5_fingerprint"]))
        if "pe_imphash" in results["static"]:
            lines.append("pe imphash|" + sanitize_generic(results["static"]["pe_imphash"]))
        if "pe_icon" in results["static"]:
            lines.append("pe icon|" + sanitize_generic(results["static"]["pe_icon"]))
        if "pe_versioninfo" in results["static"]:
            for info in results["static"]["pe_versioninfo"]:
                if info["value"]:
                    lines.append("pe ver|" + sanitize_generic(info["name"]) + " " + sanitize_generic(info["value"]))
        if "pe_sections" in results["static"]:
            for section in results["static"]["pe_sections"]:
                lines.append("pe section|" + sanitize_generic(section["name"]) + " " + "%02x" % int(float(section["entropy"])))

    return "\n".join(lines)

class Malheur(Processing):
    """ Performs classification on the generated MIST reports """
    order = 99

    def run(self):
        """Runs Malheur processing
        @return: Nothing.  Results of this processing are obtained at an arbitrary future time.
        """
        self.key = "malheur"
        basedir = os.path.join(CUCKOO_ROOT, "storage", "malheur")
        basefile = str(self.results["info"]["id"])
        outputfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", basefile, "malheur.txt")
        try:
            os.makedirs(basedir)
        except:
            pass

        mist = mist_convert(self.results)
        with open(os.path.join(basedir, basefile + ".txt"), "w") as outfile:
            outfile.write(mist)

        path, dirs, files = os.walk(basedir).next()
        if len(files) == 1:
            # if this is the first file being analyzed, reset Malheur's internal state
            subprocess.call(["malheur", "--input.format", "mist", "--input.mist_level", "2", "-r", "-o", outputfile, "increment", basedir])
        else:
            subprocess.call(["malheur", "--input.format", "mist", "--input.mist_level", "2", "-o", outputfile, "increment", basedir])

        return []

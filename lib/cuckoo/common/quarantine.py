# Copyright (C) 2015 KillerInstinct, Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import lib.cuckoo.common.office.olefile as olefile
from lib.cuckoo.common.utils import store_temp_file

def bytearray_xor(data, key):
    for i in range(len(data)):
        data[i] ^= key
    return data

def mcafee_unquarantine(file):
    if not olefile.isOleFile(file):
        return None

    with open(file, "rb") as quarfile:
        qdata = quarfile.read()

    oledata = olefile.OleFileIO(qdata)
    olefiles = oledata.listdir()
    quarfiles = list()
    for item in olefiles:
        if "Details" in item:
            details = bytearray_xor(bytearray(oledata.openstream("Details").read()), 0x6a)
        else:
            # Parse for quarantine files
            for fileobj in item:
                if "File_" in fileobj:
                    quarfiles.append(fileobj)
            decoded = dict()
            # Try and decode quarantine files (sometimes there are none)
            for item in quarfiles:
                try:
                    decoded[item] = bytearray_xor(bytearray(oledata.openstream(item).read()), 0x6a)
                except:
                    pass
            # Try and get original file name from details
            if decoded.keys():
                config = details.splitlines()
                malname = ""
                for item in decoded.keys():
                    parseit = False
                    for check in config:
                        if check.startswith("["):
                            if item in check:
                                parseit = True
                        if check == '':
                            parseit = False
                        if parseit and check.startswith("OriginalName="):
                            malname = str(check.split("\\")[-1])
                    if not malname:
                        malname = "McAfeeDequarantineFile"
                    # currently we're only returning the first found file in the quarantine file
                    return store_temp_file(decoded[item], malname)

def forefront_unquarantine(file):
    base = os.path.basename(file)
    realbase, ext = os.path.splitext(base)

    with open(file, "rb") as quarfile:
        qdata = bytearray_xor(bytearray(quarfile.read()), 0xff)
        # can't do much about the name for this case
        return store_temp_file(qdata, base)

def unquarantine(file):
    base = os.path.basename(file)
    realbase, ext = os.path.splitext(base)

    if ext.lower() == ".bup" or olefile.isOleFile(file):
        return mcafee_unquarantine(file)

    return forefront_unquarantine(file)

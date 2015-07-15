# Copyright (C) 2015 KillerInstinct, Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import struct
from binascii import crc32

import lib.cuckoo.common.office.olefile as olefile
from lib.cuckoo.common.utils import store_temp_file

def bytearray_xor(data, key):
    for i in range(len(data)):
        data[i] ^= key
    return data

def read_trend_tag(data, offset):
    """ @return a code byte and data tuple
    """
    code, length = struct.unpack("<BH", data[offset:offset+3])
    return code, bytes(data[offset+3:offset+3+length])

# Never before published, reversed & developed by Accuvant, Inc.
# We don't need most of the header fields but include them here
# for the sake of documentation

def trend_unquarantine(file):
    with open(file, "rb") as quarfile:
        qdata = quarfile.read()

    data = bytearray_xor(bytearray(qdata), 0xff)

    magic, dataoffset, numtags = struct.unpack("<IIH", data[:10])
    if magic != 0x58425356: # VSBX
        return None
    origpath = "C:\\"
    origname = "UnknownTrendFile.bin"
    platform = "Unknown"
    attributes = 0x00000000
    unknownval = 0
    basekey = 0x00000000
    encmethod = 0

    if numtags > 15:
        return None

    dataoffset += 10
    offset = 10
    for i in range(numtags):
        code, tagdata = read_trend_tag(data, offset)
        if code == 1: # original pathname
            origpath = unicode(tagdata, encoding="utf16").encode("utf8", "ignore").rstrip("\0")
        elif code == 2: # original filename
            origname = unicode(tagdata, encoding="utf16").encode("utf8", "ignore").rstrip("\0")
        elif code == 3: # platform
            platform = str(tagdata)
        elif code == 4: # file attributes
            attributes = struct.unpack("<I", tagdata)[0]
        elif code == 5: # unknown, generally 1
            unknownval = struct.unpack("<I", tagdata)[0]
        elif code == 6: # base key
            basekey = struct.unpack("<I", tagdata)[0]
        elif code == 7: # encryption method: 1 == xor FF, 2 = CRC method
            encmethod = struct.unpack("<I", tagdata)[0]
        offset += 3 + len(tagdata)

    if encmethod != 2:
        return store_temp_file(data[dataoffset:len(data)], origname)

    bytesleft = len(data) - dataoffset
    unaligned = dataoffset % 4
    firstiter = True
    curoffset = dataoffset
    while bytesleft:
        off = curoffset
        if firstiter:
            off = curoffset - unaligned
            firstiter = False
        keyval = basekey + off
        buf = struct.pack("<I", keyval)
        crc = crc32(buf) & 0xffffffff
        crcbuf = bytearray(struct.pack("<I", crc))

        for i in range(unaligned, 4):
            if not bytesleft:
                break
            data[curoffset] ^= crcbuf[i]
            curoffset += 1
            bytesleft -= 1

        unaligned = 0

    return store_temp_file(data[dataoffset:len(data)], origname)

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

    try:
        quarfile = trend_unquarantine(file)
        if quarfile:
            return quarfile
    except:
        pass

    return forefront_unquarantine(file)

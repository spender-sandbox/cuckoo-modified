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

# Never before published in an accurate form, reversed & developed by Accuvant, Inc.
# 95% black box inference from quarantine samples, 5% information obtained from
# avhostplugin.dll (mainly the format of the initial 0x1290/0xe68/0xd10 header,
# which we'll mostly ignore for this quarantine extraction)
# The SEP quarantine format is capable of storing alternate data streams, but
# we'll chop those off.
#
# Format summary:
# First dword: size of main header
# If the main header size is 0x1290, remaining file after that offset is XORed with 0x5A ('Z')
# At that offset will be the second-level header containing additional information
# about the file, original unicode path, detection name, security descriptor string, etc
#
# For older versions of the VBN format (where the first dword is 0xe68 or 0xd10) the
# original binary will be located at the offset specified as the first dword, XORed with 0x5A
# An ASCII form of the original pathname is located directly after the first dword.
#
# Similar to the Trend format, SEP uses a series of tags involving one byte codes and an associated
# value which can then describe some subsequent data (if any)
#  Code    Value Length   Extra Data
#  0x01         1            None
#  0x0A         1            None
#  0x03         4            None
#  0x06         4            None
#  0x04         8            None
#  0x08         4            NUL-terminated Unicode String (of length controlled by dword following 0x08 code)
#  0x09         4            Container (of length controlled by dword following 0x09 code)
#
# Presumably there's more "meta-meaning" behind combinations of these tags, for instance
# the container tags with extra data length of 32 preceding another container seem to be
# a hash-based ID for the information contained in the later container.  For our purposes
# we don't need to be concerned with this (for the most part).
#
# When we find a container which isn't one of the 32-byte ones preceding, we can continue our
# parsing in its contained data.
#
# When we eventually find a container with a value of 0x8 (describing the length of its contained data),
# its contained data will be the total length of its contained data, which will often itself include
# a number of containers (as large files are broken up into chunks).  Naive parsers have assumed
# some "dirty bytes" were inserted into large binaries (uncoincidentally these arose from naively
# xoring with 0xFF, mutating the container code and its associated dword length), or that "0x0900100000" was
# some magic flag.  Instead, as we walk the tags, we should only be XORing with 0xFF the contained data.
#
# To properly parse the container containing the original image, we first have to deal with its variable-length
# header.  The meaning of most of the fields are unknown, but they're unimportant for our purposes.
# At offset 8 in the header is a dword that when added to 0x1c (the initial part of the header that doesn't
# appear to change across quarantine files) brings us to the size of the original file we'll be extracting.
# The end of the header is located 12 bytes after the offset of this size.  We will walk the tags as normal,
# this header essentially just results in the initial chunk of data (if chunked) being header length smaller
# than the subsequent equal-sized chunks.  Subsequent chunks will not have any header.
#
# The total length of contained data after the header can be larger than the length of the original binary
# listed in the header.  This will happen when alternate data streams were appended to the end of the binary.
# The streams will have their own header, which we won't bother to parse as we'll just cut off the contained
# data after we reach the original file size.

def read_sep_tag(data, offset):
    """ @return a code byte, metalength, metaval, and extra data tuple
    """
    code = struct.unpack("B", data[offset:offset+1])[0]
    codeval = 0
    retdata = ""
    length = 0

    if code == 1 or code == 10:
        length = 2
        codeval = struct.unpack("B", data[offset+1:offset+2])[0]
    elif code == 3 or code == 6:
        length = 5
        codeval = struct.unpack("<I", data[offset+1:offset+5])[0]
    elif code == 4:
        length = 9
        codeval = struct.unpack("<Q", data[offset+1:offset+9])[0]
    else:
        length = 5
        codeval = struct.unpack("<I", data[offset+1:offset+5])[0]
        retdata = bytes(data[offset+5:offset+5+codeval])
    return code, length, codeval, retdata

def sep_unquarantine(file):
    filesize = os.path.getsize(file)
    with open(file, "rb") as quarfile:
        qdata = quarfile.read()

    data = bytearray(qdata)

    dataoffset = struct.unpack("<I", data[:4])[0]

    if dataoffset != 0x1290:
        # supporting older, simpler formats is trivial, will add
        # in a future commit
        return None

    # Space exists in the header for up to 384 characters of the original ASCII filename 
    origname = str(bytes(data[4:388])).rstrip('\0')
    origname = os.path.basename(origname)

    data = bytearray_xor(data, 0x5a)

    dataoffset += 0x28
    offset = dataoffset
    decode_next_container = False
    xor_next_container = False
    is_first_xor = True
    binsize = 0
    collectedsize = 0
    bindata = bytearray()
    iters = 0

    while iters < 20000: # prevent infinite loop on malformed files
        iters += 1
        code, length, codeval, tagdata = read_sep_tag(data, offset)
        extralen = len(tagdata)
        if code == 9:
            if xor_next_container:
                for i in range(len(tagdata)):
                    data[offset+5+i] ^= 0xff
                if is_first_xor:
                    headerlen = 12 + struct.unpack_from("<I", data[offset+5+8:offset+5+12])[0] + 28
                    binsize = struct.unpack_from("<I", data[offset+5+headerlen-12:offset+5+headerlen-8])[0]
                    collectedsize += len(tagdata) - headerlen
                    if collectedsize > binsize:
                        binlen = binsize
                    else:
                        binlen = collectedsize
                    bindata += data[offset+5+headerlen:offset+5+headerlen+binlen]
                    is_first_xor = False
                else:
                    binlen = len(tagdata)
                    collectedsize += binlen
                    if collectedsize > binsize:
                        binlen -= (collectedsize - binsize)
                    bindata += data[offset+5:offset+5+binlen]
            else:
                if decode_next_container:
                    extralen = 0
                    decode_next_container = False
                elif codeval == 0x10 or codeval == 0x8:
                    if codeval == 0x8:
                        xor_next_container = True
                    else:
                        xor_next_container = False
                    decode_next_container = True
        offset += length + extralen
        if offset == filesize:
            break

    return store_temp_file(bindata, origname)

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

    try:
        quarfile = sep_unquarantine(file)
        if quarfile:
            return quarfile
    except:
        pass

    return forefront_unquarantine(file)

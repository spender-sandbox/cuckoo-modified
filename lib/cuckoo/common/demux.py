# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from zipfile import ZipFile
try:
    from rarfile import RarFile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.email_utils import find_attachments_in_email
from lib.cuckoo.common.office.msgextract import Message

def demux_zip(filename, options):
    retlist = []

    try:
        # don't try to extract from office docs
        magic = File(filename).get_type()
        if "Microsoft" in magic or "Java Jar" in magic or "Composite Document File" in magic:
            return retlist
        if "PE32" in magic or "MS-DOS executable" in magic:
            return retlist

        extracted = []
        password="infected"
        fields = options.split(",")
        for field in fields:
            try:
                key, value = field.split("=", 1)
                if key == "password":
                    password = value
                    break
            except:
                pass

        with ZipFile(filename, "r") as archive:
            infolist = archive.infolist()
            for info in infolist:
                # avoid obvious bombs
                if info.file_size > 100 * 1024 * 1024 or not info.file_size:
                    continue
                # ignore directories
                if info.filename.endswith("/"):
                    continue
                base, ext = os.path.splitext(info.filename)
                basename = os.path.basename(info.filename)
                ext = ext.lower()
                if ext == "" and len(basename) and basename[0] == ".":
                    continue
                extensions = [
                    "", ".exe", ".dll", ".jar", ".pdf", ".msi", ".bin", ".scr", ".zip", ".htm", ".html", 
                    ".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm", ".docb", 
                    ".xls", ".xlt", ".xlm", ".xlsx", ".xltx", ".xlsm", ".xltm", ".xlsb", ".xla", ".xlam", ".xll", ".xlw",
                    ".ppt", ".pot", ".pps", ".pptx", ".pptm", ".potx", ".potm", ".ppam", ".ppsx", ".ppsm", ".sldx", ".sldm"
                ]
                for theext in extensions:
                    if ext == theext:
                        extracted.append(info.filename)
                        break

            options = Config()
            tmp_path = options.cuckoo.get("tmppath", "/tmp")
            target_path = os.path.join(tmp_path, "cuckoo-zip-tmp")
            if not os.path.exists(target_path):
                os.mkdir(target_path)
            tmp_dir = tempfile.mkdtemp(prefix='cuckoozip_',dir=target_path)

            for extfile in extracted:
                try:
                    retlist.append(archive.extract(extfile, path=tmp_dir, pwd=password))
                except:
                    retlist.append(archive.extract(extfile, path=tmp_dir))
    except:
        pass

    return retlist

def demux_rar(filename, options):
    retlist = []

    if not HAS_RARFILE:
        return retlist

    try:
        # don't try to auto-extract RAR SFXes
        magic = File(filename).get_type()
        if "PE32" in magic or "MS-DOS executable" in magic:
            return retlist

        extracted = []
        password="infected"
        fields = options.split(",")
        for field in fields:
            try:
                key, value = field.split("=", 1)
                if key == "password":
                    password = value
                    break
            except:
                pass

        with RarFile(filename, "r") as archive:
            infolist = archive.infolist()
            for info in infolist:
                # avoid obvious bombs
                if info.file_size > 100 * 1024 * 1024 or not info.file_size:
                    continue
                # ignore directories
                if info.filename.endswith("\\"):
                    continue
                # add some more sanity checking since RarFile invokes an external handler
                if "..\\" in info.filename:
                    continue
                base, ext = os.path.splitext(info.filename)
                basename = os.path.basename(info.filename)
                ext = ext.lower()
                if ext == "" and len(basename) and basename[0] == ".":
                    continue
                extensions = [
                    "", ".exe", ".dll", ".jar", ".pdf", ".msi", ".bin", ".scr", ".zip", ".htm", ".html", 
                    ".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm", ".docb", 
                    ".xls", ".xlt", ".xlm", ".xlsx", ".xltx", ".xlsm", ".xltm", ".xlsb", ".xla", ".xlam", ".xll", ".xlw",
                    ".ppt", ".pot", ".pps", ".pptx", ".pptm", ".potx", ".potm", ".ppam", ".ppsx", ".ppsm", ".sldx", ".sldm"
                ]
                for theext in extensions:
                    if ext == theext:
                        extracted.append(info.filename)
                        break

            options = Config()
            tmp_path = options.cuckoo.get("tmppath", "/tmp")
            target_path = os.path.join(tmp_path, "cuckoo-rar-tmp")
            if not os.path.exists(target_path):
                os.mkdir(target_path)
            tmp_dir = tempfile.mkdtemp(prefix='cuckoorar_',dir=target_path)

            for extfile in extracted:
                # RarFile differs from ZipFile in that extract() doesn't return the path of the extracted file
                # so we have to make it up ourselves
                try:
                    archive.extract(extfile, path=tmp_dir, pwd=password)
                    retlist.append(os.path.join(tmp_dir, extfile.replace("\\", "/")))
                except:
                    archive.extract(extfile, path=tmp_dir)
                    retlist.append(os.path.join(tmp_dir, extfile.replace("\\", "/")))
    except:
        pass

    return retlist


def demux_email(filename, options):
    retlist = []
    try:
        with open(filename, "rb") as openfile:
            buf = openfile.read()
            atts = find_attachments_in_email(buf, True)
            if atts and len(atts):
                for att in atts:
                    retlist.append(att[0])
    except:
        pass

    return retlist

def demux_msg(filename, options):
    retlist = []
    try:
        retlist = Message(filename).get_extracted_attachments()
    except:
        pass

    return retlist


def demux_sample(filename, package, options):
    """
    If file is a ZIP, extract its included files and return their file paths
    If file is an email, extracts its attachments and return their file paths (later we'll also extract URLs)
    """

    # if a package was specified, then don't do anything special
    # this will allow for the ZIP package to be used to analyze binaries with included DLL dependencies
    # do the same if file= is specified in the options
    if package or "file=" in options:
        return [ filename ]

    retlist = demux_zip(filename, options)
    if not retlist:
        retlist = demux_rar(filename, options)
    if not retlist:
        retlist = demux_email(filename, options)
    if not retlist:
        retlist = demux_msg(filename, options)
    # handle ZIPs/RARs inside extracted files
    if retlist:
        newretlist = []
        for item in retlist:
            zipext = demux_zip(item, options)
            if zipext:
                newretlist.extend(zipext)
            else:
                rarext = demux_rar(item, options)
                if rarext:
                    newretlist.extend(rarext)
                else:
                    newretlist.append(item)
        retlist = newretlist

    # if it wasn't a ZIP or an email or we weren't able to obtain anything interesting from either, then just submit the
    # original file

    if not retlist:
        retlist.append(filename)

    return retlist

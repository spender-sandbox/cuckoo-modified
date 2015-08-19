# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import lib.cuckoo.common.office.olefile as olefile
import lib.cuckoo.common.office.vbadeobf as vbadeobf
import lib.cuckoo.common.decoders.darkcomet as darkcomet
import lib.cuckoo.common.decoders.njrat as njrat
import logging
import os
import math
import array
import base64
import hashlib
from datetime import datetime, timedelta

from lib.cuckoo.common.icon import PEGroupIconDir
from PIL import Image
from StringIO import StringIO
from datetime import datetime, date, time

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

try:
    import pefile
    import peutils
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    import PyV8
    HAVE_PYV8 = True
except ImportError:
    HAVE_PYV8 = False

try:
    from M2Crypto import m2, BIO, X509, SMIME
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.office.oleid import OleID
from lib.cuckoo.common.office.olevba import detect_autoexec
from lib.cuckoo.common.office.olevba import detect_hex_strings
from lib.cuckoo.common.office.olevba import detect_patterns
from lib.cuckoo.common.office.olevba import detect_suspicious
from lib.cuckoo.common.office.olevba import filter_vba
from lib.cuckoo.common.office.olevba import VBA_Parser
from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.pdftools.pdfid import PDFiD, PDFiD2JSON
from lib.cuckoo.common.peepdf.PDFCore import PDFParser
from lib.cuckoo.common.peepdf.JSAnalysis import analyseJS

log = logging.getLogger(__name__)


# Obtained from
# https://github.com/erocarrera/pefile/blob/master/pefile.py
# Copyright Ero Carrera and released under the MIT License:
# https://github.com/erocarrera/pefile/blob/master/LICENSE

def _get_entropy(data):
    """ Computes the entropy value for the provided data
    @param data: data to be analyzed.
    @return: entropy value as float.
    """
    entropy = 0.0

    if len(data) == 0:
        return entropy

    occurrences = array.array('L', [0]*256)

    for x in data:
        occurrences[ord(x)] += 1

    for x in occurrences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy

# Partially taken from
# http://malwarecookbook.googlecode.com/svn/trunk/3/8/pescanner.py

def _get_filetype(data):
    """Gets filetype, uses libmagic if available.
    @param data: data to be analyzed.
    @return: file type or None.
    """
    if not HAVE_MAGIC:
        return None

    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(data)
    except:
        try:
            file_type = magic.from_buffer(data)
        except Exception:
            return None
    finally:
        try:
            ms.close()
        except:
            pass

    return file_type

class PortableExecutable:
    """PE analysis."""

    def __init__(self, file_path, results):
        """@param file_path: file path."""
        self.file_path = file_path
        self.pe = None
        self.results = results

    def add_statistic(self, name, field, value):
        self.results["statistics"]["processing"].append({
            "name": name,
            field: value,
        })

    def _get_peid_signatures(self):
        """Gets PEID signatures.
        @return: matched signatures or None.
        """
        if not self.pe:
            return None

        try:
            sig_path = os.path.join(CUCKOO_ROOT, "data",
                                    "peutils", "UserDB.TXT")
            signatures = peutils.SignatureDatabase(sig_path)
            return signatures.match_all(self.pe, ep_only=True)
        except:
            return None

    def _get_pdb_path(self):
        if not self.pe:
            return None

        try:
            for dbg in self.pe.DIRECTORY_ENTRY_DEBUG:
                dbgst = dbg.struct
                dbgdata = self.pe.__data__[dbgst.PointerToRawData:dbgst.PointerToRawData+dbgst.SizeOfData]
                if dbgst.Type == 4: #MISC
                    datatype, length, uniflag = struct.unpack_from("IIB", dbgdata)
                    return convert_to_printable(str(dbgdata[12:length]).rstrip('\0'))
                elif dbgst.Type == 2: #CODEVIEW
                    if dbgdata[:4] == "RSDS":
                        return convert_to_printable(str(dbgdata[24:]).rstrip('\0'))
                    elif dbgdata[:4] == "NB10":
                        return convert_to_printable(str(dbgdata[16:]).rstrip('\0'))
        except:
            pass

        return None

    def _get_imported_symbols(self):
        """Gets imported symbols.
        @return: imported symbols dict or None.
        """
        if not self.pe:
            return None

        imports = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    symbols = []
                    for imported_symbol in entry.imports:
                        symbol = {}
                        symbol["address"] = hex(imported_symbol.address)
                        symbol["name"] = imported_symbol.name
                        symbols.append(symbol)

                    imports_section = {}
                    imports_section["dll"] = convert_to_printable(entry.dll)
                    imports_section["imports"] = symbols
                    imports.append(imports_section)
                except:
                    continue

        return imports

    def _get_exported_dll_name(self):
        """Gets exported DLL name, if any
        @return: exported DLL name as string or None.
        """
        if not self.pe:
            return None

        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return convert_to_printable(self.pe.get_string_at_rva(self.pe.DIRECTORY_ENTRY_EXPORT.struct.Name))
        return None

    def _get_exported_symbols(self):
        """Gets exported symbols.
        @return: list of dicts of exported symbols or None.
        """
        if not self.pe:
            return None

        exports = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                symbol = {}
                symbol["address"] = hex(self.pe.OPTIONAL_HEADER.ImageBase +
                                        exported_symbol.address)
                symbol["name"] = convert_to_printable(exported_symbol.name)
                symbol["ordinal"] = exported_symbol.ordinal
                exports.append(symbol)

        return exports

    def _get_directory_entries(self):
        """Gets image directory entries.
        @return: directory entries dict or None.
        """
        if not self.pe:
            return None

        dirents = []

        for entry in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            dirent = {}
            dirent["name"] = entry.name
            dirent["virtual_address"] = "0x{0:08x}".format(entry.VirtualAddress)
            dirent["size"] = "0x{0:08x}".format(entry.Size)
            dirents.append(dirent)

        return dirents

    def _convert_section_characteristics(self, val):
        flags = [ "", "", "", "IMAGE_SCN_TYPE_NO_PAD", "", "IMAGE_SCN_CNT_CODE", "IMAGE_SCN_CNT_INITIALIZED_DATA", "IMAGE_SCN_CNT_UNINITIALIZED_DATA", "IMAGE_SCN_LNK_OTHER",
                 "IMAGE_SCN_LNK_INFO", "", "IMAGE_SCN_LNK_REMOVE", "IMAGE_SCN_LNK_COMDAT", "", "IMAGE_SCN_NO_DEFER_SPEC_EXC", "IMAGE_SCN_GPREL", "", "IMAGE_SCN_MEM_PURGEABLE",
                 "IMAGE_SCN_MEM_LOCKED", "IMAGE_SCN_MEM_PRELOAD",
                 # alignment bytes
                 "", "", "", "",
                 "IMAGE_SCN_LNK_NRELOC_OVFL", "IMAGE_SCN_MEM_DISCARDABLE", "IMAGE_SCN_MEM_NOT_CACHED", "IMAGE_SCN_MEM_NOT_PAGED", "IMAGE_SCN_MEM_SHARED", "IMAGE_SCN_MEM_EXECUTE",
                 "IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_WRITE"
                ]
        alignment = ["", "IMAGE_SCN_ALIGN_1BYTES", "IMAGE_SCN_ALIGN_2BYTES", "IMAGE_SCN_ALIGN_4BYTES", "IMAGE_SCN_ALIGN_8BYTES",
                     "IMAGE_SCN_ALIGN_16BYTES", "IMAGE_SCN_ALIGN_32BYTES", "IMAGE_SCN_ALIGN_64BYTES", "IMAGE_SCN_ALIGN_128BYTES", "IMAGE_SCN_ALIGN_256BYTES",
                     "IMAGE_SCN_ALIGN_512BYTES", "IMAGE_SCN_ALIGN_1024BYTES", "IMAGE_SCN_ALIGN_2048BYTES", "IMAGE_SCN_ALIGN_4096BYTES", "IMAGE_SCN_ALIGN_8192BYTES", ""
                    ]
        tags = []
        for idx, flagstr in enumerate(flags):
            if flags[idx] and (val & (1 << idx)):
                tags.append(flagstr)

        if val & 0x00F00000:
            alignval = (val >> 20) & 0xF
            if alignment[alignval]:
                tags.append(alignment[alignval])

        return "|".join(tags)

    def _get_sections(self):
        """Gets sections.
        @return: sections dict or None.
        """
        if not self.pe:
            return None

        sections = []

        for entry in self.pe.sections:
            try:
                section = {}
                section["name"] = convert_to_printable(entry.Name.strip("\x00"))
                section["virtual_address"] = "0x{0:08x}".format(entry.VirtualAddress)
                section["virtual_size"] = "0x{0:08x}".format(entry.Misc_VirtualSize)
                section["size_of_data"] = "0x{0:08x}".format(entry.SizeOfRawData)
                section["characteristics"] = self._convert_section_characteristics(entry.Characteristics)
                section["characteristics_raw"] = "0x{0:08x}".format(entry.Characteristics)
                section["entropy"] = "{0:.02f}".format(float(entry.get_entropy()))
                sections.append(section)
            except:
                continue

        return sections

    def _get_overlay(self):
        """Get information on the PE overlay
        @return: overlay dict or None.
        """
        if not self.pe:
            return None

        try:
            off = self.pe.get_overlay_data_start_offset()
        except:
            log.error("Your version of pefile is out of date.  Please update to the latest version on https://github.com/erocarrera/pefile")
            return None

        if off is None:
            return None
        overlay = {}
        overlay["offset"] = "0x{0:08x}".format(off)
        overlay["size"] = "0x{0:08x}".format(len(self.pe.__data__) - off)

        return overlay

    def _get_imagebase(self):
        """Get information on the Image Base
        @return: image base or None.
        """
        if not self.pe:
            return None

        return "0x{0:08x}".format(self.pe.OPTIONAL_HEADER.ImageBase)

    def _get_entrypoint(self):
        """Get full virtual address of entrypoint
        @return: entrypoint or None.
        """
        if not self.pe:
            return None

        return "0x{0:08x}".format(self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def _get_osversion(self):
        """Get minimum required OS version for PE to execute
        @return: minimum OS version or None.
        """
        if not self.pe:
            return None

        return "{0}.{1}".format(self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)

    def _get_resources(self):
        """Get resources.
        @return: resources dict or None.
        """
        if not self.pe:
            return None

        resources = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    resource = {}

                    if resource_type.name is not None:
                        name = str(resource_type.name)
                    else:
                        name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))

                    if hasattr(resource_type, "directory"):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, "directory"):
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    filetype = _get_filetype(data)
                                    language = pefile.LANG.get(resource_lang.data.lang, None)
                                    sublanguage = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                                    resource["name"] = name
                                    resource["offset"] = "0x{0:08x}".format(resource_lang.data.struct.OffsetToData)
                                    resource["size"] = "0x{0:08x}".format(resource_lang.data.struct.Size)
                                    resource["filetype"] = filetype
                                    resource["language"] = language
                                    resource["sublanguage"] = sublanguage
                                    resource["entropy"] = "{0:.02f}".format(float(_get_entropy(data)))
                                    resources.append(resource)
                except:
                    continue

        return resources

    def _get_icon_info(self):
        """Get icon in PNG format and information for searching for similar icons
        @return: tuple of (image data in PNG format encoded as base64, md5 hash of image data, md5 hash of "simplified" image for fuzzy matching)
        """
        if not self.pe:
            return None, None, None

        try:
            rt_group_icon_idx = [entry.id for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_GROUP_ICON'])
            rt_group_icon_dir = self.pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_group_icon_idx]
            entry = rt_group_icon_dir.directory.entries[0]
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            peicon = PEGroupIconDir(self.pe.get_memory_mapped_image()[offset:offset+size])
            bigwidth = 0
            bigheight = 0
            bigbpp = 0
            bigidx = -1
            iconidx = 0
            for idx,icon in enumerate(peicon.icons):
                if icon.bWidth >= bigwidth and icon.bHeight >= bigheight and icon.wBitCount >= bigbpp:
                    bigwidth = icon.bWidth
                    bigheight = icon.bHeight
                    bigbpp = icon.wBitCount
                    bigidx = icon.nID
                    iconidx = idx

            rt_icon_idx = [entry.id for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_ICON'])
            rt_icon_dir = self.pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_icon_idx]
            for entry in rt_icon_dir.directory.entries:
                if entry.id == bigidx:
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    icon = peicon.get_icon_file(iconidx, self.pe.get_memory_mapped_image()[offset:offset+size])

                    strio = StringIO()
                    output = StringIO()

                    strio.write(icon)
                    strio.seek(0)
                    img = Image.open(strio)
                    img.save(output, format="PNG")

                    img = img.resize((8,8), Image.BILINEAR)
                    img = img.convert("RGB").convert("P", palette=Image.ADAPTIVE, colors=2).convert("L")
                    lowval = img.getextrema()[0]
                    img = img.point(lambda i: 255 if i > lowval else 0)
                    img = img.convert("1")
                    simplified = bytearray(img.getdata())

                    m = hashlib.md5()
                    m.update(output.getvalue())
                    fullhash = m.hexdigest()
                    m = hashlib.md5()
                    m.update(simplified)
                    simphash = m.hexdigest()
                    return base64.b64encode(output.getvalue()), fullhash, simphash
        except:
            pass

        return None, None, None

    def _get_versioninfo(self):
        """Get version info.
        @return: info dict or None.
        """
        if not self.pe:
            return None

        infos = []
        if hasattr(self.pe, "VS_VERSIONINFO"):
            if hasattr(self.pe, "FileInfo"):
                for entry in self.pe.FileInfo:
                    try:
                        if hasattr(entry, "StringTable"):
                            for st_entry in entry.StringTable:
                                for str_entry in st_entry.entries.items():
                                    entry = {}
                                    entry["name"] = convert_to_printable(str_entry[0])
                                    entry["value"] = convert_to_printable(str_entry[1])
                                    if entry["name"] == "Translation" and len(entry["value"]) == 10:
                                        entry["value"] = "0x0" + entry["value"][2:5] + " 0x0" + entry["value"][7:10]
                                    infos.append(entry)
                        elif hasattr(entry, "Var"):
                            for var_entry in entry.Var:
                                if hasattr(var_entry, "entry"):
                                    entry = {}
                                    entry["name"] = convert_to_printable(var_entry.entry.keys()[0])
                                    entry["value"] = convert_to_printable(var_entry.entry.values()[0])
                                    if entry["name"] == "Translation" and len(entry["value"]) == 10:
                                        entry["value"] = "0x0" + entry["value"][2:5] + " 0x0" + entry["value"][7:10]
                                    infos.append(entry)
                    except:
                        continue

        return infos


    def _get_imphash(self):
        """Gets imphash.
        @return: imphash string or None.
        """
        if not self.pe:
            return None

        try:
            return self.pe.get_imphash()
        except AttributeError:
            return None

    def _get_timestamp(self):
        """Get compilation timestamp.
        @return: timestamp or None.
        """
        if not self.pe:
            return None

        try:
            pe_timestamp = self.pe.FILE_HEADER.TimeDateStamp
        except AttributeError:
            return None

        return datetime.fromtimestamp(pe_timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def _get_digital_signers(self):
        if not self.pe:
            return None

        retlist = None

        if HAVE_CRYPTO:
            address = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

            #check if file is digitally signed
            if address == 0:
                return retlist

            signature = self.pe.write()[address+8:]
            bio = BIO.MemoryBuffer(signature)

            if bio:
                swig_pkcs7 = m2.pkcs7_read_bio_der(bio.bio_ptr())

                if swig_pkcs7:
                    p7 = SMIME.PKCS7(swig_pkcs7)
                    xst = p7.get0_signers(X509.X509_Stack())
                    retlist = []
                    if xst:
                        for cert in xst:
                            sn = cert.get_serial_number()
                            sha1_fingerprint = cert.get_fingerprint('sha1').lower()
                            md5_fingerprint = cert.get_fingerprint('md5').lower()
                            subject_str = str(cert.get_subject())
                            cn = subject_str[subject_str.index("/CN=")+len("/CN="):]
                            retlist.append({"sn":str(sn), "cn":cn, "sha1_fingerprint" : sha1_fingerprint, "md5_fingerprint" : md5_fingerprint })

        return retlist

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None

        try:
            self.pe = pefile.PE(self.file_path)
        except pefile.PEFormatError:
            return None

        results = {}

        pretime = datetime.now()
        results["peid_signatures"] = self._get_peid_signatures()
        posttime = datetime.now()
        timediff = posttime - pretime
        self.add_statistic("peid", "time", float("%d.%03d" % (timediff.seconds, timediff.microseconds / 1000)))

        results["pe_imagebase"] = self._get_imagebase()
        results["pe_entrypoint"] = self._get_entrypoint()
        results["pe_osversion"] = self._get_osversion()
        results["pe_pdbpath"] = self._get_pdb_path()
        results["pe_imports"] = self._get_imported_symbols()
        results["pe_exported_dll_name"] = self._get_exported_dll_name()
        results["pe_exports"] = self._get_exported_symbols()
        results["pe_dirents"] = self._get_directory_entries()
        results["pe_sections"] = self._get_sections()
        results["pe_overlay"] = self._get_overlay()
        results["pe_resources"] = self._get_resources()
        results["pe_icon"], results["pe_icon_hash"], results["pe_icon_fuzzy"] = self._get_icon_info()
        results["pe_versioninfo"] = self._get_versioninfo()
        results["pe_imphash"] = self._get_imphash()
        results["pe_timestamp"] = self._get_timestamp()
        results["digital_signers"] = self._get_digital_signers()
        results["imported_dll_count"] = len([x for x in results["pe_imports"] if x.get("dll")])

        
        pretime = datetime.now()
        darkcomet_config = darkcomet.extract_config(self.file_path, self.pe)
        if darkcomet_config:
            results["darkcomet_config"] = darkcomet_config
        njrat_config = njrat.extract_config(self.file_path)
        if njrat_config:
            results["njrat_config"] = njrat_config
        posttime = datetime.now()
        timediff = posttime - pretime
        self.add_statistic("config_decoder", "time", float("%d.%03d" % (timediff.seconds, timediff.microseconds / 1000)))

        return results

class PDF:
    """PDF Analysis."""
    def __init__(self, file_path):
        self.file_path = file_path
        self.pdf = None

    def _parse(self, filepath):
        """Parses the PDF for static information. Uses PyV8 from peepdf to
        extract JavaScript from PDF objects.
        @param filepath: Path to file to be analyzed.
        @return: results dict or None.
        """
        # Load the PDF with PDFiD and convert it to JSON for processing
        pdf_data = PDFiD(filepath, False, True)
        pdf_json = PDFiD2JSON(pdf_data, True)
        pdfid_data = json.loads(pdf_json)[0]

        info = {}
        info["PDF Header"] = pdfid_data['pdfid']['header']
        info["Total Entropy"] = pdfid_data['pdfid']['totalEntropy']
        info['Entropy In Streams'] = pdfid_data['pdfid']['streamEntropy']
        info['Entropy Out Streams'] = pdfid_data['pdfid']['nonStreamEntropy']
        info['Count %% EOF'] = pdfid_data['pdfid']['countEof']
        info['Data After EOF'] = pdfid_data['pdfid']['countChatAfterLastEof']
        dates = pdfid_data['pdfid']['dates']['date']

        # Get streams, counts and format.
        streams = {}
        for stream in pdfid_data['pdfid']['keywords']['keyword']:
            streams[str(stream['name'])] = stream['count']

        result = {}
        result["Info"] = info
        result["Dates"] = dates
        result["Streams"] = streams

        log.debug("About to parse with PDFParser")
        parser = PDFParser()
        ret, pdf = parser.parse(filepath, True, False)
        objects = []
        retobjects = []
        count = 0
        object_counter = 1

        for i in range(len(pdf.body)):
            body = pdf.body[count]
            objects = body.objects

            for index in objects:
                oid = objects[index].id
                offset = objects[index].offset
                size = objects[index].size
                details = objects[index].object

                obj_data = {}
                obj_data["Object ID"] = oid
                obj_data["Offset"] = offset
                obj_data["Size"] = size
                if details.type == 'stream':
                    encoded_stream = details.encodedStream
                    decoded_stream = details.decodedStream
                    obj_data["File Type"] = _get_filetype(decoded_stream)[:100]
                    if HAVE_PYV8:
                        try:
                            jsdata = analyseJS(decoded_stream.strip())[0][0]
                        except Exception,e:
                            jsdata = "PyV8 failed to parse the stream."
                        if jsdata == None:
                            jsdata = "PyV8 did not detect JavaScript in the stream. (Possibly encrypted)"

                        # The following loop is required to "JSONify" the strings returned from PyV8.
                        # As PyV8 returns byte strings, we must parse out bytecode and
                        # replace it with an escape '\'. We can't use encode("string_escape")
                        # as this would mess up the new line representation which is used for
                        # beautifying the javascript code for Django's web interface.
                        ret_data = ""
                        for i in xrange(len(jsdata)):
                            if ord(jsdata[i]) > 127:
                                tmp = "\\x" + str(jsdata[i].encode("hex"))
                            else:
                                tmp = jsdata[i]
                            ret_data += tmp
                    else:
                        ret_data = "PyV8 not installed, unable to extract JavaScript."

                    obj_data["Data"] = ret_data
                    retobjects.append(obj_data)
                    object_counter += 1

                else:
                    obj_data["File Type"] = "Encoded"
                    obj_data["Data"] = "Encoded"
                    retobjects.append(obj_data)

            count += 1
            result["Objects"] = retobjects
        return result

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None
        log.debug("Starting to load PDF")
        results = self._parse(self.file_path)
        return results

class Office():
    """Office Document Static Analysis"""
    def __init__(self, file_path):
        self.file_path = file_path
        self.office = None

    # Parse a string-casted datetime object that olefile returns. This will parse
    # multiple types of timestamps including when a date is provide without a
    # time.
    def convert_dt_string(self, string):
        ctime = string.replace("datetime.datetime", "")
        ctime = ctime.replace("(","")
        ctime = ctime.replace(")","")
        ctime = "".join(ctime).split(", ")
        # Parse date, set to None if we don't have any/not enough data
        if len(ctime) >= 3:
            docdate = date(int(ctime[0]), int(ctime[1]), int(ctime[2])).strftime("%B %d, %Y")
        else:
            docdate = None
        # Parse if we are missing minutes and seconds field
        if len(ctime) == 4:
            doctime = time(int(ctime[3])).strftime("%H")
        # Parse if we are missing seconds field
        elif len(ctime) == 5:
            doctime = time(int(ctime[3]), int(ctime[4])).strftime("%H:%M")
        # Parse a full datetime string
        elif len(ctime) == 6:
            doctime = time(int(ctime[3]), int(ctime[4]), int(ctime[5])).strftime("%H:%M:%S")
        else:
            doctime = None

        if docdate and doctime:
            return docdate + " " + doctime
        elif docdate:
            return docdate
        else:
            return "None"

    def _parse(self, filepath):
        """Parses an office document for static information.
        Currently (as per olefile) the following formats are supported:
        - Word 97-2003 (.doc, .dot), Word 2007+ (.docm, .dotm)
        - Excel 97-2003 (.xls), Excel 2007+ (.xlsm, .xlsb)
        - PowerPoint 2007+ (.pptm, .ppsm)

        @param filepath: Path to the file to be analyzed.
        @return: results dict or None
        """

        results = dict()
        vba = VBA_Parser(filepath)
        results["Metadata"] = dict()
        # The bulk of the metadata checks are in the OLE Structures
        # So don't check if we're dealing with XML.
        if olefile.isOleFile(filepath):
            ole = olefile.OleFileIO(filepath)
            meta = ole.get_metadata()
            results["Metadata"] = meta.get_meta()
            # Fix up some output formatting
            buf = self.convert_dt_string(results["Metadata"]["SummaryInformation"]["create_time"])
            results["Metadata"]["SummaryInformation"]["create_time"] = buf
            buf = self.convert_dt_string(results["Metadata"]["SummaryInformation"]["last_saved_time"])
            results["Metadata"]["SummaryInformation"]["last_saved_time"] = buf
            ole.close()
        if vba.detect_vba_macros():
            results["Metadata"]["HasMacros"] = "Yes"
            results["Macro"] = dict()
            results["Macro"]["Code"] = dict()
            ctr = 0
            # Create IOC and category vars. We do this before processing the
            # macro(s) to avoid overwriting data when there are multiple
            # macros in a single file.
            results["Macro"]["Analysis"] = dict()
            results["Macro"]["Analysis"]["AutoExec"] = list()
            results["Macro"]["Analysis"]["Suspicious"] = list()
            results["Macro"]["Analysis"]["IOCs"] = list()
            results["Macro"]["Analysis"]["HexStrings"] = list()
            for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                vba_code = filter_vba(vba_code)
                if vba_code.strip() != '':
                    # Handle all macros
                    ctr += 1
                    outputname = "Macro" + str(ctr)
                    results["Macro"]["Code"][outputname] = list()
                    results["Macro"]["Code"][outputname].append((convert_to_printable(vba_filename),convert_to_printable(vba_code)))
                    autoexec = detect_autoexec(vba_code)
                    suspicious = detect_suspicious(vba_code)
                    iocs = vbadeobf.parse_macro(vba_code)
                    hex_strs = detect_hex_strings(vba_code)
                    if autoexec:
                        for keyword, description in autoexec:
                            results["Macro"]["Analysis"]["AutoExec"].append((keyword, description))
                    if suspicious:
                        for keyword, description in suspicious:
                            results["Macro"]["Analysis"]["Suspicious"].append((keyword, description))
                    if iocs:
                        for pattern, match in iocs:
                            results["Macro"]["Analysis"]["IOCs"].append((pattern, match))
                    if hex_strs:
                        for encoded, decoded in hex_strs:
                            results["Macro"]["Analysis"]["HexStrings"].append((encoded, decoded))
            # Delete and keys which had no results. Otherwise we pollute the
            # Django interface with null data.
            if results["Macro"]["Analysis"]["AutoExec"] == []:
                del results["Macro"]["Analysis"]["AutoExec"]
            if results["Macro"]["Analysis"]["Suspicious"] == []:
                del results["Macro"]["Analysis"]["Suspicious"]
            if results["Macro"]["Analysis"]["IOCs"] == []:
                del results["Macro"]["Analysis"]["IOCs"]
            if results["Macro"]["Analysis"]["HexStrings"] == []:
                del results["Macro"]["Analysis"]["HexStrings"]

        else:
            results["Metadata"]["HasMacros"] = "No"

        oleid = OleID(filepath)
        indicators = oleid.check()
        for indicator in indicators:
            if indicator.name == "Word Document" and indicator.value == True:
                results["Metadata"]["DocumentType"] = indicator.name
            if indicator.name == "Excel Workbook" and indicator.value == True:
                results["Metadata"]["DocumentType"] = indicator.name
            if indicator.name == "PowerPoint Presentation" and indicator.value == True:
                results["Metadata"]["DocumentType"] = indicator.name

        return results

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None
        results = self._parse(self.file_path)
        return results


class Static(Processing):
    """Static analysis."""

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "static"
        static = {}

        if self.task["category"] == "file":
            thetype = File(self.file_path).get_type()
            if HAVE_PEFILE and ("PE32" in thetype or "MS-DOS executable" in thetype):
                static = PortableExecutable(self.file_path, self.results).run()
            elif "PDF" in thetype:
                static = PDF(self.file_path).run()
            elif "Word 2007" in thetype or "Excel 2007" in thetype or "PowerPoint 2007" in thetype:
                static = Office(self.file_path).run()
            elif "Composite Document File" in thetype:
                static = Office(self.file_path).run()
            # It's possible to fool libmagic into thinking our 2007+ file is a
            # zip. So until we have static analysis for zip files, we can use
            # oleid to fail us out silently, yeilding no static analysis
            # results for actual zip files.
            elif "Zip archive data, at least v2.0" in thetype:
                static = Office(self.file_path).run()

        return static

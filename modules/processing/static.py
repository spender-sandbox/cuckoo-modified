# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import lib.cuckoo.common.office.olefile as olefile
import lib.cuckoo.common.office.vbadeobf as vbadeobf
import logging
import os
import base64

from lib.cuckoo.common.icon import PEIcon
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

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path
        self.pe = None


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

    def _get_exported_symbols(self):
        """Gets exported symbols.
        @return: exported symbols dict or None.
        """
        if not self.pe:
            return None

        exports = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                symbol = {}
                symbol["address"] = hex(self.pe.OPTIONAL_HEADER.ImageBase +
                                        exported_symbol.address)
                symbol["name"] = exported_symbol.name
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

        off = self.pe.get_overlay_data_start_offset()
        if off is None:
            return None
        overlay = {}
        overlay["offset"] = "0x{0:08x}".format(off)
        overlay["size"] = "0x{0:08x}".format(len(self.pe.__data__) - off)

        return overlay

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
                                    resources.append(resource)
                except:
                    continue

        return resources

    def _get_icon(self):
        """Get icon in PNG format.
        @return: image data in PNG format, encoded as base64
        """
        if not self.pe:
            return None

        # .ico extraction from https://gist.github.com/arbor-jjones/0ead6f9a9f91e420f7c8

        try:
            rt_string_idx = [entry.id for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_GROUP_ICON'])
            rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
            rt_string_directory = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE['RT_GROUP_ICON']][0]
            entry = rt_string_directory.directory.entries[-1] # gives the highest res icon
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[offset:offset+size]
            icon = data[:18]+'\x16\x00\x00\x00'
 
            rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_ICON'])
            rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
            rt_string_directory = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE['RT_ICON']][0]
            entry = rt_string_directory.directory.entries[-1] # gives the highest res icon
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            icon += pe.get_memory_mapped_image()[offset:offset+size]

            strio = StringIO()
            output = StringIO()
            strio.write(icon)
            strio.seek(0)
            img = Image.open(strio)
            img.save(output, format="PNG")
            return base64.b64encode(output.getvalue())
        except:
            return None

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
                                    infos.append(entry)
                        elif hasattr(entry, "Var"):
                            for var_entry in entry.Var:
                                if hasattr(var_entry, "entry"):
                                    entry = {}
                                    entry["name"] = convert_to_printable(var_entry.entry.keys()[0])
                                    entry["value"] = convert_to_printable(var_entry.entry.values()[0])
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
        results["peid_signatures"] = self._get_peid_signatures()
        results["pe_imports"] = self._get_imported_symbols()
        results["pe_exports"] = self._get_exported_symbols()
        results["pe_dirents"] = self._get_directory_entries()
        results["pe_sections"] = self._get_sections()
        results["pe_overlay"] = self._get_overlay()
        results["pe_resources"] = self._get_resources()
        results["pe_icon"] = self._get_icon()
        results["pe_versioninfo"] = self._get_versioninfo()
        results["pe_imphash"] = self._get_imphash()
        results["pe_timestamp"] = self._get_timestamp()
        results["imported_dll_count"] = len([x for x in results["pe_imports"] if x.get("dll")])

        if HAVE_CRYPTO:
            address = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

            #check if file is digitally signed
            if address == 0:
                return results

            signature = self.pe.write()[address+8:]
            bio = BIO.MemoryBuffer(signature)

            if bio:
                swig_pkcs7 = m2.pkcs7_read_bio_der(bio.bio_ptr())

                if swig_pkcs7:
                    p7 = SMIME.PKCS7(swig_pkcs7)
                    xst = p7.get0_signers(X509.X509_Stack())
                    results["digital_signers"] = []
                    if xst:
                        for cert in xst:
                            sn = cert.get_serial_number()
                            sha1_fingerprint = cert.get_fingerprint('sha1').lower()
                            md5_fingerprint = cert.get_fingerprint('md5').lower()
                            subject_str = str(cert.get_subject())
                            cn = subject_str[subject_str.index("/CN=")+len("/CN="):]
                            results["digital_signers"].append({"sn":str(sn), "cn":cn, "sha1_fingerprint" : sha1_fingerprint, "md5_fingerprint" : md5_fingerprint })

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
            if HAVE_PEFILE and ("PE32" in thetype or thetype == "MS-DOS executable"):
                static = PortableExecutable(self.file_path).run()
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

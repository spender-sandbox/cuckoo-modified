# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
from datetime import datetime

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

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
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
            return signatures.match(self.pe, ep_only=True)
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
                section["entropy"] = entry.get_entropy()
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
        results["pe_versioninfo"] = self._get_versioninfo()
        results["pe_imphash"] = self._get_imphash()
        results["pe_timestamp"] = self._get_timestamp()
        results["imported_dll_count"] = len([x for x in results["pe_imports"] if x.get("dll")])
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

        return static

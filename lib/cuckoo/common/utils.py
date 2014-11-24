# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import shutil
import ntpath
import string
import tempfile
import xmlrpclib
from datetime import datetime

from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT

try:
    import chardet
    HAVE_CHARDET = True
except ImportError:
    HAVE_CHARDET = False

def create_folders(root=".", folders=[]):
    """Create directories.
    @param root: root path.
    @param folders: folders list to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
    for folder in folders:
        create_folder(root, folder)

def create_folder(root=".", folder=None):
    """Create directory.
    @param root: root path.
    @param folder: folder name to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
    folder_path = os.path.join(root, folder)
    if folder and not os.path.isdir(folder_path):
        try:
            os.makedirs(folder_path)
        except OSError:
            raise CuckooOperationalError("Unable to create folder: %s" %
                                         folder_path)


def delete_folder(folder):
    """Delete a folder and all its subdirectories.
    @param folder: path to delete.
    @raise CuckooOperationalError: if fails to delete folder.
    """
    if os.path.exists(folder):
        try:
            shutil.rmtree(folder)
        except OSError:
            raise CuckooOperationalError("Unable to delete folder: "
                                         "{0}".format(folder))


# Don't allow all characters in "string.printable", as newlines, carriage
# returns, tabs, \x0b, and \x0c may mess up reports.
# The above is true, but apparently we only care about \x0b and \x0c given
# the code below
PRINTABLE_CHARACTERS = \
    string.letters + string.digits + string.punctuation + " \t\r\n"


def convert_char(c):
    """Escapes characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if c in PRINTABLE_CHARACTERS:
        return c
    else:
        return "\\x%02x" % ord(c)


def is_printable(s):
    """ Test if a string is printable."""
    for c in s:
        if c not in PRINTABLE_CHARACTERS:
            return False
    return True

def convert_to_printable(s):
    """Convert char to printable.
    @param s: string.
    @return: sanitized string.
    """
    if is_printable(s):
        return s
    return "".join(convert_char(c) for c in s)

def pretty_print_retval(category, api_name, status, retval):
    """Creates pretty-printed versions of an API return value
    @return: pretty-printed version of the call's return value, or None if no conversion exists
    """
    if status:
        return None
    val = None
    try:
        val = int(retval, 16)
    except ValueError:
        return None
    return {
            0x00000103 : "NO_MORE_ITEMS",
            0x80000005 : "BUFFER_OVERFLOW",
            0x80000006 : "NO_MORE_FILES",
            0xc0000001 : "UNSUCCESSFUL",
            0xc0000002 : "NOT_IMPLEMENTED",
            0xc0000004 : "INFO_LENGTH_MISMATCH",
            0xc0000005 : "ACCESS_VIOLATION",
            0xc0000008 : "INVALID_HANDLE",
            0xc000000b : "INVALID_CID",
            0xc000000d : "INVALID_PARAMETER",
            0xc000000f : "NO_SUCH_FILE",
            0xc0000011 : "END_OF_FILE",
            0xc0000018 : "CONFLICTING_ADDRESSES",
            0xc0000023 : "BUFFER_TOO_SMALL",
            0xc0000024 : "OBJECT_TYPE_MISMATCH",
            0xc0000033 : "OBJECT_NAME_INVALID",
            0xc0000034 : "OBJECT_NAME_NOT_FOUND",
            0xc0000039 : "OBJECT_PATH_INVALID",
            0xc000003a : "OBJECT_PATH_NOT_FOUND",
            0xc000003c : "DATA_OVERRUN",
            0xc00000ba : "FILE_IS_A_DIRECTORY",
            0xc0000135 : "DLL_NOT_FOUND",
            0xc0000139 : "ENTRYPOINT_NOT_FOUND"
    }.get(val, None)

def pretty_print_arg(category, api_name, arg_name, arg_val):
    """Creates pretty-printed versions of API arguments that convert raw values in common APIs to their named-enumeration forms
    @return: pretty-printed version of the argument value provided, or None if no conversion exists
    """
    if api_name == "NtCreateSection" and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        res = []
        if val == 0xf001f:
            return "SECTION_ALL_ACCESS"
        if val & 0xf0000:
            res.append("STANDARD_RIGHTS_REQUIRED")
            val &= ~0xf0000
        if val & 1:
            res.append("SECTION_QUERY")
            val &= ~1
        if val & 4:
            res.append("SECTION_MAP_READ")
            val &= ~4
        if val & 2:
            res.append("SECTION_MAP_WRITE")
            val &= ~2
        if val & 8:
            res.append("SECTION_MAP_EXECUTE")
            val &= ~8
        if val & 0x10:
            res.append("SECTION_EXTEND_SIZE")
            val &= ~0x10
        if val & 0x20:
            res.append("SECTION_MAP_EXECUTE_EXPLICIT")
            val &= ~0x20
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "CreateToolhelp32Snapshot" and arg_name == "Flags":
        val = int(arg_val, 16)
        res = []
        if val == 0xf:
            return "TH32CS_SNAPALL"
        if val & 1:
            res.append("TH32CS_SNAPHEAPLIST")
            val &= ~1
        if val & 2:
            res.append("TH32CS_SNAPPROCESS")
            val &= ~2
        if val & 4:
            res.append("TH32CS_SNAPTHREAD")
            val &= ~4
        if val & 8:
            res.append("TH32CS_SNAPMODULE")
            val &= ~8
        if val & 0x10:
            res.append("TH32CS_SNAPMODULE32")
            val &= ~0x10
        if val & 0x80000000:
            res.append("TH32CS_INHERIT")
            val &= ~0x80000000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "Algid":
        val = int(arg_val, 16)
        return {
                0x8001 : "MD2",
                0x8002 : "MD4",
                0x8003 : "MD5",
                0x8004 : "SHA1",
                0x8005 : "MAC",
                0x8009 : "HMAC",
                0x2400 : "RSA Public Key Signature",
                0x2200 : "DSA Public Key Signature",
                0xa400 : "RSA Public Key Exchange",
                0x6602 : "RC2",
                0x6801 : "RC4",
                0x6601 : "DES",
                0x6603 : "3DES",
                0x6609 : "Two-key 3DES"
        }.get(val, None);
    elif api_name == "SHGetFolderPathW" and arg_name == "Folder":
        val = int(arg_val, 16)
        res = []
        if val & 0x800:
            res.append("CSIDL_FLAG_PER_USER_INIT")
            val &= ~0x800
        if val & 0x1000:
            res.append("CSIDL_FLAG_NO_ALIAS")
            val &= ~0x1000
        if val & 0x2000:
            res.append("CSIDL_FLAG_DONT_UNEXPAND")
            val &= ~0x2000
        if val & 0x4000:
            res.append("CSIDL_FLAG_DONT_VERIFY")
            val &= ~0x4000
        if val & 0x8000:
            res.append("CSIDL_FLAG_CREATE")
            val &= ~0x8000
        folder = {
                0 : "CSIDL_DESKTOP",
                1 : "CSIDL_INTERNET",
                2 : "CSIDL_PROGRAMS",
                3 : "CSIDL_CONTROLS",
                4 : "CSIDL_PRINTERS",
                5 : "CSIDL_MYDOCUMENTS",
                6 : "CSIDL_FAVORITES",
                7 : "CSIDL_STARTUP",
                8 : "CSIDL_RECENT",
                9 : "CSIDL_SENDTO",
                10 : "CSIDL_BITBUCKET",
                11 : "CSIDL_STARTMENU",
                13 : "CSIDL_MYMUSIC",
                14 : "CSIDL_MYVIDEO",
                16 : "CSIDL_DESKTOPDIRECTORY",
                17 : "CSIDL_DRIVES",
                18 : "CSIDL_NETWORK",
                19 : "CSIDL_NETHOOD",
                20 : "CSIDL_FONTS",
                21 : "CSIDL_TEMPLATES",
                22 : "CSIDL_COMMON_STARTMENU",
                23 : "CSIDL_COMMON_PROGRAMS",
                24 : "CSIDL_COMMON_STARTUP",
                25 : "CSIDL_COMMON_DESKTOPDIRECTORY",
                26 : "CSIDL_APPDATA",
                27 : "CSIDL_PRINTHOOD",
                28 : "CSIDL_LOCAL_APPDATA",
                29 : "CSIDL_ALTSTARTUP",
                30 : "CSIDL_COMMON_ALTSTARTUP",
                31 : "CSIDL_COMMON_FAVORITES",
                32 : "CSIDL_INTERNET_CACHE",
                33 : "CSIDL_COOKIES",
                34 : "CSIDL_HISTORY",
                35 : "CSIDL_COMMON_APPDATA",
                36 : "CSIDL_WINDOWS",
                37 : "CSIDL_SYSTEM",
                38 : "CSIDL_PROGRAM_FILES",
                39 : "CSIDL_MYPICTURES",
                40 : "CSIDL_PROFILE",
                41 : "CSIDL_SYSTEMX86",
                42 : "CSIDL_PROGRAM_FILESX86",
                43 : "CSIDL_PROGRAM_FILES_COMMON",
                44 : "CSIDL_PROGRAM_FILES_COMMONX86",
                45 : "CSIDL_COMMON_TEMPLATES",
                46 : "CSIDL_COMMON_DOCUMENTS",
                47 : "CSIDL_COMMON_ADMINTOOLS",
                48 : "CSIDL_ADMINTOOLS",
                49 : "CSIDL_CONNECTIONS",
                53 : "CSIDL_COMMON_MUSIC",
                54 : "CSIDL_COMMON_PICTURES",
                55 : "CSIDL_COMMON_VIDEO",
                56 : "CSIDL_RESOURCES",
                57 : "CSIDL_RESOURCES_LOCALIZED",
                58 : "CSIDL_COMMON_OEM_LINKS",
                59 : "CSIDL_CDBURN_AREA",
                61 : "CSIDL_COMPUTERSNEARME"
            }.get(val, None)
        if folder:
            res.append(folder)
        else:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "HookIdentifier":
        val = int(arg_val, 10)
        return {
                # cuckoo chooses not to represent this value properly as a -1
                4294967295 : "WH_MSGFILTER",
                0 : "WH_JOURNALRECORD",
                1 : "WH_JOURNALPLAYBACK",
                2 : "WH_KEYBOARD",
                3 : "WH_GETMESSAGE",
                4 : "WH_CALLWNDPROC",
                5 : "WH_CBT",
                6 : "WH_SYSMSGFILTER",
                7 : "WH_MOUSE",
                8 : "WH_HARDWARE",
                9 : "WH_DEBUG",
                10 : "WH_SHELL",
                11 : "WH_FOREGROUNDIDLE",
                12 : "WH_CALLWNDPROCRET",
                13 : "WH_KEYBOARD_LL",
                14 : "WH_MOUSE_LL"
        }.get(val, None)                
    elif arg_name == "Disposition":
        val = int(arg_val, 10)
        return {
                1 : "REG_CREATED_NEW_KEY",
                2 : "REG_OPENED_EXISTING_KEY"
        }.get(val, None)
    elif arg_name == "CreateDisposition":
        val = int(arg_val, 16)
        return {
                0 : "FILE_SUPERSEDE",
                1 : "FILE_OPEN",
                2 : "FILE_CREATE",
                3 : "FILE_OPEN_IF",
                4 : "FILE_OVERWRITE",
                5 : "FILE_OVERWRITE_IF"
        }.get(val, None)
    elif arg_name == "ShareAccess":
        val = int(arg_val, 10)
        res = []
        if val & 1:
            res.append("FILE_SHARE_READ")
            val &= ~1
        if val & 2:
            res.append("FILE_SHARE_WRITE")
            val &= ~2
        if val & 4:
            res.append("FILE_SHARE_DELETE")
            val &= ~4
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif category == "registry" and arg_name == "Type":
        val = int(arg_val, 16)
        return {
                0 : "REG_NONE",
                1 : "REG_SZ",
                2 : "REG_EXPAND_SZ",
                3 : "REG_BINARY",
                4 : "REG_DWORD",
                5 : "REG_DWORD_BIG_ENDIAN",
                6 : "REG_LINK",
                7 : "REG_MULTI_SZ",
                8 : "REG_RESOURCE_LIST",
                9 : "REG_FULL_RESOURCE_DESCRIPTOR",
                10 : "REG_RESOURCE_REQUIREMENTS_LIST",
                11 : "REG_QWORD"
        }.get(val, None)
    elif (api_name == "OpenSCManagerW" or api_name == "OpenSCManagerW") and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        res = []
        if val == 0x02000000:
            return "MAXIMUM_ALLOWED";
        if val == 0xf003f:
            return "SC_MANAGER_ALL_ACCESS";
        if val & 0x0001:
            res.append("SC_MANAGER_CONNECT")
            val &= ~0x0001
        if val & 0x0002:
            res.append("SC_MANAGER_CREATE_SERVICE")
            val &= ~0x0002
        if val & 0x0004:
            res.append("SC_MANAGER_ENUMERATE_SERVICE")
            val &= ~0x0004
        if val & 0x0008:
            res.append("SC_MANAGER_LOCK")
            val &= ~0x0008
        if val & 0x0010:
            res.append("SC_MANAGER_QUERY_LOCK_STATUS")
            val &= ~0x0010
        if val & 0x0020:
            res.append("SC_MANAGER_MODIFY_BOOT_CONFIG")
            val &= ~0x0020
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif category == "services" and arg_name == "ControlCode":
        val = int(arg_val, 10)
        return {
            1 : "SERVICE_CONTROL_STOP",
            2 : "SERVICE_CONTROL_PAUSE",
            3 : "SERVICE_CONTROL_CONTINUE",
            4 : "SERVICE_CONTROL_INTERROGATE",
            6 : "SERVICE_CONTROL_PARAMCHANGE",
            7 : "SERVICE_CONTROL_NETBINDADD",
            8 : "SERVICE_CONTROL_NETBINDREMOVE",
            9 : "SERVICE_CONTROL_NETBINDENABLE",
            10 : "SERVICE_CONTROL_NETBINDDISABLE"
        }.get(val, None)
    elif category == "services" and arg_name == "ErrorControl":
        val = int(arg_val, 10)
        return {
            0 : "SERVICE_ERROR_IGNORE",
            1 : "SERVICE_ERROR_NORMAL",
            2 : "SERVICE_ERROR_SEVERE",
            3 : "SERVICE_ERROR_CRITICAL"
        }.get(val, None)
    elif category == "services" and arg_name == "StartType":
        val = int(arg_val, 10)
        return {
            0 : "SERVICE_BOOT_START",
            1 : "SERVICE_SYSTEM_START",
            2 : "SERVICE_AUTO_START",
            3 : "SERVICE_DEMAND_START",
            4 : "SERVICE_DISABLED"
        }.get(val, None)
    elif category == "services" and arg_name == "ServiceType":
        val = int(arg_val, 10)
        retstr = {
            1 : "SERVICE_KERNEL_DRIVER",
            2 : "SERVICE_FILE_SYSTEM_DRIVER",
            4 : "SERVICE_ADAPTER",
            8 : "SERVICE_RECOGNIZED_DRIVER",
            16 : "SERVICE_WIN32_OWN_PROCESS",
            32 : "SERVICE_WIN32_SHARE_PROCESS"
        }.get(val, None)
        if val & 0x130:
            retstr += "|SERVICE_INTERACTIVE_PROCESS"
        return retstr
    elif category == "services" and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        res = []
        if val == 0x02000000:
            return "MAXIMUM_ALLOWED";
        if val == 0xf01ff:
            return "SERVICE_ALL_ACCESS";
        if val & 0x0001:
            res.append("SERVICE_QUERY_CONFIG")
            val &= ~0x0001
        if val & 0x0002:
            res.append("SERVICE_CHANGE_CONFIG")
            val &= ~0x0002
        if val & 0x0004:
            res.append("SERVICE_QUERY_STATUS")
            val &= ~0x0004
        if val & 0x0008:
            res.append("SERVICE_ENUMERATE_DEPENDENTS")
            val &= ~0x0008
        if val & 0x0010:
            res.append("SERVICE_START")
            val &= ~0x0010
        if val & 0x0020:
            res.append("SERVICE_STOP")
            val &= ~0x0020
        if val & 0x0040:
            res.append("SERVICE_PAUSE_CONTINUE")
            val &= ~0x0040
        if val & 0x0080:
            res.append("SERVICE_INTERROGATE")
            val &= ~0x0080
        if val & 0x0100:
            res.append("SERVICE_USER_DEFINED_CONTROL")
            val &= ~0x0100
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif category == "registry" and (arg_name == "Access" or arg_name == "DesiredAccess"):
        val = int(arg_val, 16)
        res = []
        if val == 0x02000000:
            return "MAXIMUM_ALLOWED";
        if val == 0xf003f:
            return "KEY_ALL_ACCESS";
        elif val == 0x20019:
            return "KEY_READ"
        elif val == 0x20006:
            return "KEY_WRITE"
        elif val == 0x2001f:
            return "KEY_READ|KEY_WRITE"

        if val & 0x0001:
            res.append("KEY_QUERY_VALUE")
            val &= ~0x0001
        if val & 0x0002:
            res.append("KEY_SET_VALUE")
            val &= ~0x0002
        if val & 0x0004:
            res.append("KEY_CREATE_SUB_KEY")
            val &= ~0x0004
        if val & 0x0008:
            res.append("KEY_ENUMERATE_SUB_KEYS")
            val &= ~0x0008
        if val & 0x0010:
            res.append("KEY_NOTIFY")
            val &= ~0x0010
        if val & 0x0020:
            res.append("KEY_CREATE_LINK")
            val &= ~0x0020
        if val & 0x0100:
            res.append("KEY_WOW64_64KEY")
            val &= ~0x0100
        if val & 0x0f0000:
            res.append("STANDARD_RIGHTS_REQUIRED")
            val &= ~0x0f0000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "IoControlCode":
        val = int(arg_val, 16)
        return {
                0x1200b : "IOCTL_AFD_START_LISTEN",
                0x12010 : "IOCTL_AFD_ACCEPT",
                0x1201b : "IOCTL_AFD_RECV_DATAGRAM",
                0x12024 : "IOCTL_AFD_SELECT",
                0x12023 : "IOCTL_AFD_SEND_DATAGRAM",
                0x1207b : "IOCTL_AFD_GET_INFO",
                0x1203b : "IOCTL_AFD_SET_INFO",
                0x12047 : "IOCTL_AFD_SET_CONTEXT",
                0x12003 : "IOCTL_AFD_BIND",
                0x12007 : "IOCTL_AFD_CONNECT",
                0x1202b : "IOCTL_AFD_DISCONNECT",
                0x120bf : "IOCTL_AFD_DEFER_ACCEPT",
                0x12017 : "IOCTL_AFD_RECV",
                0x1201f : "IOCTL_AFD_SEND",
                0x12087 : "IOCTL_AFD_EVENT_SELECT",
                0x1208b : "IOCTL_AFD_ENUM_NETWORK_EVENTS",
                0x4d008 : "IOCTL_SCSI_MINIPORT",
                0x4d014 : "IOCTL_SCSI_PASS_THROUGH_DIRECT",
                0x70000 : "IOCTL_DISK_GET_DRIVE_GEOMETRY",
                0x7405c : "IOCTL_DISK_GET_LENGTH_INFO",
                0x90018 : "FSCTL_LOCK_VOLUME",
                0x9001c : "FSCTL_UNLOCK_VOLUME",
                0x900a8 : "FSCTL_GET_REPARSE_POINT",
                0x2d0c10 : "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER",
                0x2d1080 : "IOCTL_STORAGE_GET_DEVICE_NUMBER",
                0x2d1400 : "IOCTL_STORAGE_QUERY_PROPERTY",
                0x398000 : "IOCTL_KSEC_REGISTER_LSA_PROCESS",
                0x390004 : "IOCTL_KSEC_1",
                0x390008 : "IOCTL_KSEC_RANDOM_FILL_BUFFER",
                0x39000e : "IOCTL_KSEC_ENCRYPT_PROCESS",
                0x390012 : "IOCTL_KSEC_DECRYPT_PROCESS",
                0x390016 : "IOCTL_KSEC_ENCRYPT_CROSS_PROCESS",
                0x39001a : "IOCTL_KSEC_DECRYPT_CROSS_PROCESS",
                0x39001e : "IOCTL_KSEC_ENCRYPT_SAME_LOGON",
                0x390022 : "IOCTL_KSEC_DECRYPT_SAME_LOGON",
                0x390038 : "IOCTL_KSEC_REGISTER_EXTENSION",
                0x4d0008 : "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME",
                0x560000 : "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
                0x6d0008 : "IOCTL_MOUNTMGR_QUERY_POINTS",
                0x6d0030 : "IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH",
                0x6d0034 : "IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS"
        }.get(val, None)
    elif arg_name == "Protection" or arg_name == "Win32Protect":
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("PAGE_NOACCESS")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("PAGE_READONLY")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("PAGE_READWRITE")
            val &= ~0x00000004
        if val & 0x00000008:
            res.append("PAGE_WRITECOPY")
            val &= ~0x00000008
        if val & 0x00000010:
            res.append("PAGE_EXECUTE")
            val &= ~0x00000010
        if val & 0x00000020:
            res.append("PAGE_EXECUTE_READ")
            val &= ~0x00000020
        if val & 0x00000040:
            res.append("PAGE_EXECUTE_READWRITE")
            val &= ~0x00000040
        if val & 0x00000080:
            res.append("PAGE_EXECUTE_WRITECOPY")
            val &= ~0x00000080
        if val & 0x00000100:
            res.append("PAGE_GUARD")
            val &= ~0x00000100
        if val & 0x00000200:
            res.append("PAGE_NOCACHE")
            val &= ~0x00000200
        if val & 0x00000400:
            res.append("PAGE_WRITECOMBINE")
            val &= ~0x00000400
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "CreateProcessInternalW" and arg_name == "CreationFlags":
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("DEBUG_PROCESS")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("DEBUG_ONLY_THIS_PROCESS")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("CREATE_SUSPENDED")
            val &= ~0x00000004
        if val & 0x00000008:
            res.append("DETACHED_PROCESS")
            val &= ~0x00000008
        if val & 0x00000020:
            res.append("NORMAL_PRIORITY_CLASS")
            val &= ~0x00000020
        if val & 0x00000040:
            res.append("IDLE_PRIORITY_CLASS")
            val &= ~0x00000040
        if val & 0x00000080:
            res.append("HIGH_PRIORITY_CLASS")
            val &= ~0x00000080
        if val & 0x00000400:
            res.append("CREATE_UNICODE_ENVIRONMENT")
            val &= ~0x00000400
        if val & 0x00040000:
            res.append("CREATE_PROTECTED_PROCESS")
            val &= ~0x00040000
        if val & 0x02000000:
            res.append("CREATE_PRESERVE_CODE_AUTHZ_LEVEL")
            val &= ~0x02000000
        if val & 0x08000000:
            res.append("CREATE_NO_WINDOW")
            val &= ~0x08000000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "MoveFileWithProgressW" and arg_name == "Flags":
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("MOVEFILE_REPLACE_EXISTING")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("MOVEFILE_COPY_ALLOWED")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("MOVEFILE_DELAY_UNTIL_REBOOT")
            val &= ~0x00000004
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "FileAttributes":
        val = int(arg_val, 16)
        res = []
        if val == 0x00000080:
            return "FILE_ATTRIBUTE_NORMAL"
        if val & 0x00000001:
            res.append("FILE_ATTRIBUTE_READONLY")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("FILE_ATTRIBUTE_HIDDEN")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("FILE_ATTRIBUTE_SYSTEM")
            val &= ~0x00000004
        if val & 0x00000010:
            res.append("FILE_ATTRIBUTE_DIRECTORY")
            val &= ~0x00000010
        if val & 0x00000020:
            res.append("FILE_ATTRIBUTE_ARCHIVE")
            val &= ~0x00000020
        if val & 0x00000040:
            res.append("FILE_ATTRIBUTE_DEVICE")
            val &= ~0x00000040
        if val & 0x00000100:
            res.append("FILE_ATTRIBUTE_TEMPORARY")
            val &= ~0x00000100
        if val & 0x00000200:
            res.append("FILE_ATTRIBUTE_SPARSE_FILE")
            val &= ~0x00000200
        if val & 0x00000400:
            res.append("FILE_ATTRIBUTE_REPARSE_POINT")
            val &= ~0x00000400
        if val & 0x00000800:
            res.append("FILE_ATTRIBUTE_COMPRESSED")
            val &= ~0x00000800
        if val & 0x00001000:
            res.append("FILE_ATTRIBUTE_OFFLINE")
            val &= ~0x00001000
        if val & 0x00002000:
            res.append("FILE_ATTRIBUTE_NOT_CONTENT_INDEXED")
            val &= ~0x00002000
        if val & 0x00004000:
            res.append("FILE_ATTRIBUTE_ENCRYPTED")
            val &= ~0x00004000
        if val & 0x00008000:
            res.append("FILE_ATTRIBUTE_VIRTUAL")
            val &= ~0x00008000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif (api_name == "NtCreateFile" or api_name == "NtOpenFile" or api_name == "NtCreateDirectoryObject" or api_name == "NtOpenDirectoryObject") and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        remove = 0
        res = []
        if val & 0x80000000:
            res.append("GENERIC_READ")
            remove |= 0x80000000
        if val & 0x40000000:
            res.append("GENERIC_WRITE")
            remove |= 0x40000000
        if val & 0x20000000:
            res.append("GENERIC_EXECUTE")
            remove |= 0x20000000
        if val & 0x10000000:
            res.append("GENERIC_ALL")
            remove |= 0x10000000
        if val & 0x02000000:
            res.append("MAXIMUM_ALLOWED")
            remove |= 0x02000000
        if (val & 0x1f01ff) == 0x1f01ff:
            res.append("FILE_ALL_ACCESS")
            val &= ~0x1f01ff
        if (val & 0x120089) == 0x120089:
            res.append("FILE_GENERIC_READ")
            remove |= 0x120089
        if (val & 0x120116) == 0x120116:
            res.append("FILE_GENERIC_WRITE")
            remove |= 0x120116
        if (val & 0x1200a0) == 0x1200a0:
            res.append("FILE_GENERIC_EXECUTE")
            remove |= 0x1200a0
        val &= ~remove
        # for values 1 -> 0x20, these can have different meanings depending on whether
        # it's a file or a directory operated on -- choose file by default since
        # we don't have enough information to make an accurate determination
        if val & 0x00000001:
            res.append("FILE_READ_ACCESS")
            remove |= 0x00000001
        if val & 0x00000002:
            res.append("FILE_WRITE_ACCESS")
            remove |= 0x00000002
        if val & 0x00000004:
            res.append("FILE_APPEND_DATA")
            remove |= 0x00000004
        if val & 0x00000008:
            res.append("FILE_READ_EA")
            remove |= 0x00000008
        if val & 0x00000010:
            res.append("FILE_WRITE_EA")
            remove |= 0x00000010
        if val & 0x00000020:
            res.append("FILE_EXECUTE")
            remove |= 0x00000020
        if val & 0x00000040:
            res.append("FILE_DELETE_CHILD")
            remove |= 0x00000040
        if val & 0x00000080:
            res.append("FILE_READ_ATTRIBUTES")
            remove |= 0x00000080
        if val & 0x00000100:
            res.append("FILE_WRITE_ATTRIBUTES")
            remove |= 0x00000100
        if val & 0x00010000:
            res.append("DELETE")
            remove |= 0x00010000
        if val & 0x00020000:
            res.append("READ_CONTROL")
            remove |= 0x00020000
        if val & 0x00040000:
            res.append("WRITE_DAC")
            remove |= 0x00040000
        if val & 0x00080000:
            res.append("WRITE_OWNER")
            remove |= 0x00080000
        if val & 0x00100000:
            res.append("SYNCHRONIZE")
            remove |= 0x00100000
        if val & 0x01000000:
            res.append("ACCESS_SYSTEM_SECURITY")
            remove |= 0x01000000
        val &= ~remove
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "NtOpenProcess" and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        remove = 0
        res = []
        if val & 0x80000000:
            res.append("GENERIC_READ")
            remove |= 0x80000000
        if val & 0x40000000:
            res.append("GENERIC_WRITE")
            remove |= 0x40000000
        if val & 0x20000000:
            res.append("GENERIC_EXECUTE")
            remove |= 0x20000000
        if val & 0x10000000:
            res.append("GENERIC_ALL")
            remove |= 0x10000000
        if val & 0x02000000:
            res.append("MAXIMUM_ALLOWED")
            remove |= 0x02000000
        # for >= vista
        if (val & 0x1fffff) == 0x1fffff:
            res.append("PROCESS_ALL_ACCESS")
            val &= ~0x1fffff
        # for < vista
        if (val & 0x1f03ff) == 0x1f0fff:
            res.append("PROCESS_ALL_ACCESS")
            val &= ~0x1f03ff
        val &= ~remove
        if val & 0x0001:
            res.append("PROCESS_TERMINATE")
            remove |= 0x0001
        if val & 0x0002:
            res.append("PROCESS_CREATE_THREAD")
            remove |= 0x0002
        if val & 0x0004:
            res.append("PROCESS_SET_SESSIONID")
            remove |= 0x0004
        if val & 0x0008:
            res.append("PROCESS_VM_OPERATION")
            remove |= 0x0008
        if val & 0x0010:
            res.append("PROCESS_VM_READ")
            remove |= 0x0010
        if val & 0x0020:
            res.append("PROCESS_VM_WRITE")
            remove |= 0x0020
        if val & 0x0040:
            res.append("PROCESS_DUP_HANDLE")
            remove |= 0x0040
        if val & 0x0080:
            res.append("PROCESS_CREATE_PROCESS")
            remove |= 0x0080
        if val & 0x0100:
            res.append("PROCESS_SET_QUOTA")
            remove |= 0x0100
        if val & 0x0200:
            res.append("PROCESS_SET_INFORMATION")
            remove |= 0x0200
        if val & 0x0400:
            res.append("PROCESS_QUERY_INFORMATION")
            remove |= 0x0400
        if val & 0x0800:
            res.append("PROCESS_SUSPEND_RESUME")
            remove |= 0x0800
        if val & 0x1000:
            res.append("PROCESS_QUERY_LIMITED_INFORMATION")
            remove |= 0x1000
        val &= ~remove
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "NtOpenThread" and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        remove = 0
        res = []
        if val & 0x80000000:
            res.append("GENERIC_READ")
            remove |= 0x80000000
        if val & 0x40000000:
            res.append("GENERIC_WRITE")
            remove |= 0x40000000
        if val & 0x20000000:
            res.append("GENERIC_EXECUTE")
            remove |= 0x20000000
        if val & 0x10000000:
            res.append("GENERIC_ALL")
            remove |= 0x10000000
        if val & 0x02000000:
            res.append("MAXIMUM_ALLOWED")
            remove |= 0x02000000
        # for >= vista
        if (val & 0x1fffff) == 0x1fffff:
            res.append("THREAD_ALL_ACCESS")
            val &= ~0x1fffff
        # for < vista
        if (val & 0x1f03ff) == 0x1f03ff:
            res.append("THREAD_ALL_ACCESS")
            val &= ~0x1f03ff
        val &= ~remove
        if val & 0x0001:
            res.append("THREAD_TERMINATE")
            remove |= 0x0001
        if val & 0x0002:
            res.append("THREAD_SUSPEND_RESUME")
            remove |= 0x0002
        if val & 0x0008:
            res.append("THREAD_GET_CONTEXT")
            remove |= 0x0008
        if val & 0x0010:
            res.append("THREAD_SET_CONTEXT")
            remove |= 0x0010
        if val & 0x0020:
            res.append("THREAD_SET_INFORMATION")
            remove |= 0x0020
        if val & 0x0040:
            res.append("THREAD_QUERY_INFORMATION")
            remove |= 0x0040
        if val & 0x0080:
            res.append("THREAD_SET_THREAD_TOKEN")
            remove |= 0x0080
        if val & 0x0100:
            res.append("THREAD_IMPERSONATE")
            remove |= 0x0100
        if val & 0x0200:
            res.append("THREAD_DIRECT_IMPERSONATION")
            remove |= 0x0200
        if val & 0x0400:
            res.append("THREAD_SET_LIMITED_INFORMATION")
            remove |= 0x0400
        if val & 0x0800:
            res.append("THREAD_QUERY_LIMITED_INFORMATION")
            remove |= 0x0800
        val &= ~remove
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "FileInformationClass":
        val = int(arg_val, 10)
        return {
                1 : "FileDirectoryInformation",
                2 : "FileFullDirectoryInformation",
                3 : "FileBothDirectoryInformation",
                4 : "FileBasicInformation",
                5 : "FileStandardInformation",
                6 : "FileInternalInformation",
                7 : "FileEaInformation",
                8 : "FileAccessInformation",
                9 : "FileNameInformation",
                10 : "FileRenameInformation",
                11 : "FileLinkInformation",
                12 : "FileNamesInformation",
                13 : "FileDispositionInformation",
                14 : "FilePositionInformation",
                15 : "FileFullEaInformation",
                16 : "FileModeInformation",
                17 : "FileAlignmentInformation",
                18 : "FileAllInformation",
                19 : "FileAllocationInformation",
                20 : "FileEndOfFileInformation",
                21 : "FileAlternativeNameInformation",
                22 : "FileStreamInformation",
                23 : "FilePipeInformation",
                24 : "FilePipeLocalInformation",
                25 : "FilePipeRemoteInformation",
                26 : "FileMailslotQueryInformation",
                27 : "FileMailslotSetInformation",
                28 : "FileCompressionInformation",
                29 : "FileObjectIdInformation",
                30 : "FileCompletionInformation",
                31 : "FileMoveClusterInformation",
                32 : "FileQuotaInformation",
                33 : "FileReparsePointInformation",
                34 : "FileNetworkOpenInformation",
                35 : "FileAttributeTagInformation",
                36 : "FileTrackingInformation",
                37 : "FileIdBothDirectoryInformation",
                38 : "FileIdFullDirectoryInformation",
                39 : "FileShortNameInformation",
                40 : "FileIoCompletionNotificationInformation",
                41 : "FileIoStatusBlockRangeInformation",
                42 : "FileIoPriorityHintInformation",
                43 : "FileSfioReserveInformation",
                44 : "FileSfioVolumeInformation",
                45 : "FileHardLinkInformation",
                46 : "FileProcessIdsUsingFileInformation",
                47 : "FileNormalizedNameInformation",
                48 : "FileNetworkPhysicalNameInformation",
                49 : "FileIdGlobalTxDirectoryInformation",
                50 : "FileIsRemoteDeviceInformation",
                51 : "FileAttributeCacheInformation",
                52 : "FileNumaNodeInformation",
                53 : "FileStandardLinkInformation",
                54 : "FileRemoteProtocolInformation",
                55 : "FileReplaceCompletionInformation",
                56 : "FileMaximumInformation"
         }.get(val, None)
    elif arg_name == "Show":
        val = int(arg_val, 10)
        return {
                0 : "SW_HIDE",
                1 : "SW_SHOWNORMAL",
                2 : "SW_SHOWMINIMIZED",
                3 : "SW_SHOWMAXIMIZED",
                4 : "SW_SHOWNOACTIVATE",
                5 : "SW_SHOW",
                6 : "SW_MINIMIZE",
                7 : "SW_SHOWMINNOACTIVE",
                8 : "SW_SHOWNA",
                9 : "SW_RESTORE",
                10 : "SW_SHOWDEFAULT",
                11 : "SW_FORCEMINIMIZE"
        }.get(val, None)
    elif arg_name == "Registry":
        val = int(arg_val, 16)
        return {
                0x80000000 : "HKEY_CLASSES_ROOT",
                0x80000001 : "HKEY_CURRENT_USER",
                0x80000002 : "HKEY_LOCAL_MACHINE",
                0x80000003 : "HKEY_USERS",
                0x80000004 : "HKEY_PERFORMANCE_DATA",
                0x80000005 : "HKEY_CURRENT_CONFIG",
                0x80000006 : "HKEY_DYN_DATA"
        }.get(val, None)

    return None

def datetime_to_iso(timestamp):
    """Parse a datatime string and returns a datetime in iso format.
    @param timestamp: timestamp string
    @return: ISO datetime
    """
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").isoformat()

def get_filename_from_path(path):
    """Cross-platform filename extraction from path.
    @param path: file path.
    @return: filename.
    """
    dirpath, filename = ntpath.split(path)
    return filename if filename else ntpath.basename(dirpath)

def store_temp_file(filedata, filename, path=None):
    """Store a temporary file.
    @param filedata: content of the original file.
    @param filename: name of the original file.
    @param path: optional path for temp directory.
    @return: path to the temporary file.
    """
    filename = get_filename_from_path(filename)

    # Reduce length (100 is arbitrary).
    filename = filename[:100]

    options = Config()
    # Create temporary directory path.
    if path:
        target_path = path
    else:
        tmp_path = options.cuckoo.get("tmppath", "/tmp")
        target_path = os.path.join(tmp_path, "cuckoo-tmp")
    if not os.path.exists(target_path):
        os.mkdir(target_path)

    tmp_dir = tempfile.mkdtemp(prefix="upload_", dir=target_path)
    tmp_file_path = os.path.join(tmp_dir, filename)
    with open(tmp_file_path, "wb") as tmp_file:
        # If filedata is file object, do chunked copy.
        if hasattr(filedata, "read"):
            chunk = filedata.read(1024)
            while chunk:
                tmp_file.write(chunk)
                chunk = filedata.read(1024)
        else:
            tmp_file.write(filedata)

    return tmp_file_path

class TimeoutServer(xmlrpclib.ServerProxy):
    """Timeout server for XMLRPC.
    XMLRPC + timeout - still a bit ugly - but at least gets rid of setdefaulttimeout
    inspired by http://stackoverflow.com/questions/372365/set-timeout-for-xmlrpclib-serverproxy
    (although their stuff was messy, this is cleaner)
    @see: http://stackoverflow.com/questions/372365/set-timeout-for-xmlrpclib-serverproxy
    """
    def __init__(self, *args, **kwargs):
        timeout = kwargs.pop("timeout", None)
        kwargs["transport"] = TimeoutTransport(timeout=timeout)
        xmlrpclib.ServerProxy.__init__(self, *args, **kwargs)

    def _set_timeout(self, timeout):
        t = self._ServerProxy__transport
        t.timeout = timeout
        # If we still have a socket we need to update that as well.
        if hasattr(t, "_connection") and t._connection[1] and t._connection[1].sock:
            t._connection[1].sock.settimeout(timeout)

class TimeoutTransport(xmlrpclib.Transport):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop("timeout", None)
        xmlrpclib.Transport.__init__(self, *args, **kwargs)

    def make_connection(self, *args, **kwargs):
        conn = xmlrpclib.Transport.make_connection(self, *args, **kwargs)
        if self.timeout is not None:
            conn.timeout = self.timeout
        return conn

class Singleton(type):
    """Singleton.
    @see: http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

def logtime(dt):
    """Formats time like a logger does, for the csv output
       (e.g. "2013-01-25 13:21:44,590")
    @param dt: datetime object
    @return: time string
    """
    t = time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())
    s = "%s,%03d" % (t, dt.microsecond/1000)
    return s

def time_from_cuckoomon(s):
    """Parse time string received from cuckoomon via netlog
    @param s: time string
    @return: datetime object
    """
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S,%f")

def to_unicode(s):
    """Attempt to fix non uft-8 string into utf-8. It tries to guess input encoding,
    if fail retry with a replace strategy (so undetectable chars will be escaped).
    @see: fuller list of encodings at http://docs.python.org/library/codecs.html#standard-encodings
    """

    def brute_enc(s2):
        """Trying to decode via simple brute forcing."""
        encodings = ("ascii", "utf8", "latin1")
        for enc in encodings:
            try:
                return unicode(s2, enc)
            except UnicodeDecodeError:
                pass
        return None

    def chardet_enc(s2):
        """Guess encoding via chardet."""
        enc = chardet.detect(s2)["encoding"]

        try:
            return unicode(s2, enc)
        except UnicodeDecodeError:
            pass
        return None

    # If already in unicode, skip.
    if isinstance(s, unicode):
        return s

    # First try to decode against a little set of common encodings.
    result = brute_enc(s)

    # Try via chardet.
    if not result and HAVE_CHARDET:
        result = chardet_enc(s)

    # If not possible to convert the input string, try again with
    # a replace strategy.
    if not result:
        result = unicode(s, errors="replace")

    return result

def sanitize_filename(x):
    """Kind of awful but necessary sanitizing of filenames to
    get rid of unicode problems."""
    out = ""
    for c in x:
        if c in string.letters + string.digits + " _-.":
            out += c
        else:
            out += "_"

    return out

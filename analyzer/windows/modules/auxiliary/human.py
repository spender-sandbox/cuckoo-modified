#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import random
import logging
from threading import Thread
from ctypes import WINFUNCTYPE, POINTER
from ctypes import c_bool, c_int, create_unicode_buffer

from lib.common.abstracts import Auxiliary
from lib.common.defines import KERNEL32, USER32
from lib.common.defines import WM_GETTEXT, WM_GETTEXTLENGTH, WM_CLOSE, BM_CLICK

log = logging.getLogger(__name__)

EnumWindowsProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))
EnumChildProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))

RESOLUTION = {
    "x": USER32.GetSystemMetrics(0),
    "y": USER32.GetSystemMetrics(1)
}

def foreach_child(hwnd, lparam):
    # List of buttons labels to click.
    buttons = [
        "yes",
        "ok",
        "accept",
        "next",
        "install",
        "run",
        "agree",
        "enable",
        "don't send",
        "don't save",
        "continue",
        "unzip",
        "open",
        "close the program"
    ]

    # List of buttons labels to not click.
    dontclick = [
        "don't run",
    ]

    classname = create_unicode_buffer(50)
    USER32.GetClassNameW(hwnd, classname, 50)

    # Check if the class of the child is button.
    if classname.value == "Button":
        # Get the text of the button.
        length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        text = create_unicode_buffer(length + 1)
        USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)

        # Check if the button is set as "clickable" and click it.
        for button in buttons:
            if button in text.value.lower():
                for btn in dontclick:
                    if btn in text.value.lower():
                        return False
                log.info("Found button \"%s\", clicking it" % text.value)
                USER32.SetForegroundWindow(hwnd)
                KERNEL32.Sleep(1000)
                USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)
        # Don't search for childs (USER32.EnumChildWindows).
        return False
    else:
        # Recursively search for childs (USER32.EnumChildWindows).
        return True


# Callback procedure invoked for every enumerated window.
def foreach_window(hwnd, lparam):
    # If the window is visible, enumerate its child objects, looking
    # for buttons.
    if USER32.IsWindowVisible(hwnd):
        USER32.EnumChildWindows(hwnd, EnumChildProc(foreach_child), 0)
    return True

def move_mouse():
    x = random.randint(0, RESOLUTION["x"])
    y = random.randint(0, RESOLUTION["y"])

    # Originally was:
    # USER32.mouse_event(0x8000, x, y, 0, None)
    # Changed to SetCurorPos, since using GetCursorPos would not detect
    # the mouse events. This actually moves the cursor around which might
    # cause some unintended activity on the desktop. We might want to make
    # this featur optional.
    USER32.SetCursorPos(x, y)

def click_mouse():
    # Move mouse to top-middle position.
    USER32.SetCursorPos(RESOLUTION["x"] / 2, 0)
    # Mouse down.
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    # Mouse up.
    USER32.mouse_event(4, 0, 0, 0, None)

# Callback procedure invoked for every enumerated window.
def get_office_window(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        if "- Microsoft" in text:
            # send ALT+F4 equivalent
            USER32.SendMessageW(USER32.GetForegroundWindow(), WM_CLOSE, None, None)
    return True

class Human(Auxiliary, Thread):
    """Human after all"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        seconds = 0
        nohuman = self.options.get("nohuman")
        if nohuman:
            return True
        file_type = self.config.file_type
        file_name = self.config.file_name
        officedoc = False
        if "Rich Text Format" in file_type or "Microsoft Word" in file_type or \
            "Microsoft Office Word" in file_type or file_name.endswith((".doc", ".docx", ".rtf")):
            officedoc = True
        elif "Microsoft Office Excel" in file_type or "Microsoft Excel" in file_type or \
            file_name.endswith((".xls", ".xlsx")):
            officedoc = True
        elif "Microsoft PowerPoint" in file_type or \
            file_name.endswith((".ppt", ".pptx", ".pps", ".ppsx", ".pptm", ".potm", ".potx", ".ppsm")):
            officedoc = True

        while self.do_run:
            if officedoc and seconds == 30:
                USER32.EnumWindows(EnumWindowsProc(get_office_window), 0)

            click_mouse()
            move_mouse()
            USER32.EnumWindows(EnumWindowsProc(foreach_window), 0)
            KERNEL32.Sleep(1000)
            seconds += 1

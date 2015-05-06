# Copyright (C) 2010-2015 Cuckoo Foundation, Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging
import traceback
from ctypes import create_string_buffer
from ctypes import byref, c_int, sizeof
from threading import Thread

from lib.common.defines import KERNEL32
from lib.common.defines import ERROR_MORE_DATA, ERROR_PIPE_CONNECTED

log = logging.getLogger()

BUFSIZE = 512
LOGBUFSIZE = 16384

class LogServer(Thread):
    """Cuckoo Log Server.

    This Log Server receives the BSON-encoded logs from cuckoomon loaded in an individual process
    and forwards them on to the resultserver on the process' behalf, avoiding the need for winsock
    in cuckoomon and escaping some deadlock issues that can arise from the use of winsock APIs at
    crucial points in process execution (like the final termination) and also allowing us to again
    use synchronous logging without side-effects.
    """

    def __init__(self, h_pipe, result_ip, result_port):
        """@param pipe_name: Cuckoo Log Server PIPE name."""
        Thread.__init__(self)
        self.h_pipe = h_pipe
        self.resultserver_ip = result_ip
        self.resultserver_port = result_port
        self.resultserver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.resultserver_socket.connect((self.resultserver_ip, self.resultserver_port))
        self.do_run = True

    def stop(self):
        """Stop Log Server."""
        self.do_run = False

    def handle_logs(self):
        # Read the data submitted to the Log Server.
        while True:
            data = ""
            while True:
                bytes_read = c_int(0)
                buf = create_string_buffer(LOGBUFSIZE)
                success = KERNEL32.ReadFile(self.h_pipe,
                                            buf,
                                            sizeof(buf),
                                            byref(bytes_read),
                                            None)

                data += buf.value

                if success or KERNEL32.GetLastError() != ERROR_MORE_DATA:
                    break

            # got an entire message, send it off to the resultserver
            if data:
                self.resultserver_socket.sendall(data)

    def run(self):
        """Create and run Log Server.
        @return: operation status.
        """
        try:
            while self.do_run:
                # Create the Named Pipe.
                # If we receive a connection to the pipe, we invoke the handler.
                if KERNEL32.ConnectNamedPipe(self.h_pipe, None) or KERNEL32.GetLastError() == ERROR_PIPE_CONNECTED:
                    self.handle_logs()

                KERNEL32.CloseHandle(self.h_pipe)
                self.resultserver_socket.close()
    
            return True
        except Exception as e:
            error_exc = traceback.format_exc()
            log.exception(error_exc)
            return True


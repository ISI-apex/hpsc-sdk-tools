import sys
import telnetlib
import json
#import pprint

class QMP:
    def __init__(self, host, port, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose

        self.cl = telnetlib.Telnet(self.host, self.port)
        reply = self.cl.read_until(b"\r\n")
        # required handshake
        self.cl.write(b'{"execute": "qmp_capabilities"}')
        reply = self.cl.read_until(b"\r\n")

    def command(self, cmd, **args):
        req = json.dumps({"execute": cmd, "arguments": args})
        if self.verbose:
            print(req)
        self.cl.write(req.encode())
        reply = self.cl.read_until(b"\r\n")
        # some commands print multiple newlines; we must eat them, otherwise
        # the next request will read them and return immediately.
        try:
            self.cl.read_eager()
        except BlockingIOError:
            pass
        reply = reply.decode()
        if self.verbose:
            print(reply)
        return json.loads(reply)

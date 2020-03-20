import sys
import telnetlib
import json
import time
#import pprint

class QMP:
    def __init__(self, host, port, timeout=None, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose

        start_time = time.time()
        while True:
            try:
                self.cl = telnetlib.Telnet(self.host, self.port)
                reply = self.cl.read_until(b"\r\n")
                # required handshake
                self.cl.write(b'{"execute": "qmp_capabilities"}')
                reply = self.cl.read_until(b"\r\n")
                return
            except ConnectionRefusedError as e:
                if timeout is None or time.time() - start_time > timeout:
                    raise e
                time.sleep(2)
                continue

    def command(self, cmd, **args):
        req = json.dumps({"execute": cmd, "arguments": args})
        if self.verbose:
            print(req)

        # some replies print multiple newlines; we must eat whatever
        # garbage before beginning the RPC. Also, when other clients
        # send requests (e.g. GDB continue), the reply gets sent
        # over our channel too.... no clear way to deal with it, other
        # than make JSON errors non-fatal (see below)
        try:
            self.cl.read_eager()
        except BlockingIOError:
            pass
        self.cl.write(req.encode())
        reply = self.cl.read_until(b"\r\n")
        reply = reply.decode()
        if self.verbose:
            print(reply)
        try:
            return json.loads(reply)
        except json.decoder.JSONDecodeError as e:
            print("ERROR: failed to parse JSON:", e, file=sys.stderr)
            print("  Bad JSON input:", reply)

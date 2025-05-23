import asyncio
import os
import signal
import sys
import logging

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

MITM_PORT = 8443

class Addon:
    def __init__(self):
        self.num_requests = 0

    def request(self, flow):
        self.num_requests += 1
        print(f"[REQUEST {self.num_requests}] {flow.request.url}")

addons = [Addon()]

def run():
    opts = options.Options(listen_host='0.0.0.0', listen_port=MITM_PORT)
    m = DumpMaster(opts)
    for addon in addons:
        m.addons.add(addon)

    def shutdown():
        print("[*] Shutting down…")
        m.shutdown()  # FIX: directly call, not create_task()

    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    print(f"[*] mitmproxy running on port {MITM_PORT}…")
    try:
        m.run()
    except KeyboardInterrupt:
        print("[*] KeyboardInterrupt received, shutting down…")
        m.shutdown()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run()

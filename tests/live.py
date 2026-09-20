"""Kleiner Helfer: ASGI-App in einem Thread auf einem freien Port starten."""
import socket
import threading
import time

import uvicorn


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LiveServer:
    def __init__(self, app, port=None):
        self.port = port or free_port()
        self.base = "http://127.0.0.1:%d" % self.port
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port,
                                                    log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("Server startete nicht")

    def stop(self):
        self.server.should_exit = True
        self.thread.join(5)

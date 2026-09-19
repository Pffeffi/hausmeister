"""Ende-zu-Ende ueber echtes HTTP: uvicorn im Thread + offizieller MCP-Client."""
import socket
import threading
import time
import unittest

import anyio
import httpx2
import uvicorn
from mcp.client.client import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from tests.fakes import FakeClient
from manager import Manager
from server import build_app

TOKEN = "t" * 40


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeClient()
        cls.port = free_port()
        app = build_app(Manager(cls.fake, ["Jellyfin", "Spoolman"], cooldown_s=0), TOKEN,
                        allowed_hosts=["127.0.0.1:%d" % cls.port])
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="warning"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.05)
        cls.url = "http://127.0.0.1:%d/mcp" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(5)

    def post(self, headers):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        h = {"Accept": "application/json, text/event-stream", **headers}
        return httpx2.post(self.url, json=body, headers=h, timeout=5)

    def test_missing_or_wrong_token_is_401(self):
        self.assertEqual(self.post({}).status_code, 401)
        self.assertEqual(self.post({"Authorization": "Bearer falsch"}).status_code, 401)
        self.assertEqual(self.post({"Authorization": "Bearer " + TOKEN + "x"}).status_code, 401)

    def test_foreign_host_header_rejected(self):
        r = self.post({"Authorization": "Bearer " + TOKEN, "Host": "evil.example:1234"})
        self.assertNotIn(r.status_code, (200, 202))

    def call(self, fn):
        async def main():
            http = create_mcp_http_client(headers={"Authorization": "Bearer " + TOKEN})
            async with http, Client(streamable_http_client(self.url, http_client=http)) as client:
                return await fn(client)
        return anyio.run(main)

    def test_tools_exposed_are_exactly_the_allowed_ones(self):
        async def fn(c):
            return await c.list_tools()
        tools = {t.name: t for t in self.call(fn).tools}
        self.assertEqual(set(tools), {"container_list", "container_status", "container_logs",
                                      "server_metrics", "container_start", "container_stop",
                                      "container_restart"})
        self.assertTrue(tools["container_logs"].annotations.read_only_hint)
        self.assertTrue(tools["container_restart"].annotations.destructive_hint)

    def test_call_tools(self):
        async def fn(c):
            lst = await c.call_tool("container_list", {})
            denied = await c.call_tool("container_restart", {"name": "cms-db"})
            ok = await c.call_tool("container_restart", {"name": "jellyfin"})
            return lst, denied, ok
        lst, denied, ok = self.call(fn)
        self.assertFalse(lst.is_error)
        self.assertIn("cms-db", str(lst.content))
        self.assertTrue(denied.is_error)
        self.assertIn("Whitelist", str(denied.content))
        self.assertFalse(ok.is_error, ok.content)
        self.assertIn(("start", "srv:Jellyfin"), self.fake.calls)
        self.assertNotIn(("stop", "srv:cms-db"), self.fake.calls)


if __name__ == "__main__":
    unittest.main()

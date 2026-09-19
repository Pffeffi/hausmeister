import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unraid_api import UnraidError  # noqa: E402


class FakeClient:
    """Stellt die Unraid-API nach; protokolliert jede Mutation."""

    def __init__(self):
        self.calls = []
        self.state = {"Jellyfin": "RUNNING", "Spoolman": "EXITED", "cms-db": "RUNNING"}
        self.fail_start = False

    def containers(self):
        return [{"id": "srv:" + n, "name": n, "image": n.lower() + ":latest", "state": s,
                 "status": "Up" if s == "RUNNING" else "Exited", "autoStart": True,
                 "updateAvailable": False} for n, s in self.state.items()]

    def logs(self, cid, tail):
        self.calls.append(("logs", cid, tail))
        return [{"timestamp": "2026-09-19T10:00:00Z", "message": "line %d password=hunter2" % i}
                for i in range(tail + 50)]

    def start(self, cid):
        self.calls.append(("start", cid))
        if self.fail_start:
            raise UnraidError("boom")
        self.state[cid.split(":", 1)[1]] = "RUNNING"
        return {"state": "RUNNING", "status": "Up 1 second"}

    def stop(self, cid):
        self.calls.append(("stop", cid))
        self.state[cid.split(":", 1)[1]] = "EXITED"
        return {"state": "EXITED", "status": "Exited (0)"}

    def metrics(self):
        return {"metrics": {"cpu": {"percentTotal": 12.345},
                            "memory": {"percentTotal": 40.0, "total": "32000000000",
                                       "available": "19000000000", "swapUsed": "0"},
                            "temperature": {"sensors": [{"name": "cpu", "current": {"value": 50}}]}},
                "info": {"os": {"uptime": "2026-09-01T00:00:00Z"}},
                "array": {"state": "STARTED", "capacity": {"kilobytes": {"used": "4000000000", "total": "8000000000"}},
                          "disks": [{"name": "disk1", "temp": 35, "status": "DISK_OK", "numErrors": 0}],
                          "parities": [], "caches": []}}

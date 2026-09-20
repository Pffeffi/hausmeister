import json
import os
import tempfile
import unittest

from tests import fakes  # noqa: F401  (setzt sys.path)
from docker_logs import DockerLogFiles

CID = "a" * 64
PREFIXED = "srv123:" + CID


def write_log(d, name, records):
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        for ts, stream, msg in records:
            f.write(json.dumps({"log": msg + "\n", "stream": stream, "time": ts}) + "\n")
    return path


class DockerLogFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = self.tmp.name
        self.dir = os.path.join(self.base, CID)
        os.makedirs(self.dir)
        self.src = DockerLogFiles(self.base)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reads_stdout_and_stderr(self):
        write_log(self.dir, CID + "-json.log", [
            ("2026-09-20T10:00:00Z", "stdout", "start"),
            ("2026-09-20T10:00:01Z", "stderr", "INFO etwas passiert"),
        ])
        got = self.src.tail(PREFIXED, 10)
        self.assertEqual([(g["stream"], g["message"]) for g in got],
                         [("stdout", "start"), ("stderr", "INFO etwas passiert")])

    def test_tail_limits_and_keeps_the_newest(self):
        write_log(self.dir, CID + "-json.log",
                  [("2026-09-20T10:00:%02dZ" % i, "stderr", "Zeile %d" % i) for i in range(50)])
        got = self.src.tail(PREFIXED, 5)
        self.assertEqual([g["message"] for g in got], ["Zeile %d" % i for i in range(45, 50)])

    def test_rotated_files_come_first(self):
        write_log(self.dir, CID + "-json.log.1", [("t1", "stdout", "alt-1"), ("t2", "stdout", "alt-2")])
        write_log(self.dir, CID + "-json.log", [("t3", "stdout", "neu")])
        self.assertEqual([g["message"] for g in self.src.tail(PREFIXED, 3)], ["alt-1", "alt-2", "neu"])

    def test_broken_lines_are_skipped(self):
        path = write_log(self.dir, CID + "-json.log", [("t1", "stdout", "gut")])
        with open(path, "a", encoding="utf-8") as f:
            f.write("kein json\n")
            f.write(json.dumps({"stream": "stdout", "time": "t2"}) + "\n")   # ohne 'log'
        self.assertEqual([g["message"] for g in self.src.tail(PREFIXED, 10)], ["gut"])

    def test_only_valid_ids_are_accepted(self):
        for bad in ["../../etc/passwd", "srv:../" + CID, CID[:-1], "", None,
                    "srv:" + CID.upper() + "x", "srv:/" + CID]:
            self.assertEqual(self.src.tail(bad, 5), [], bad)

    def test_missing_directory_or_file_is_harmless(self):
        self.assertEqual(self.src.tail("srv:" + "b" * 64, 5), [])
        self.assertEqual(DockerLogFiles(os.path.join(self.base, "gibtsnicht")).available(), False)
        self.assertEqual(DockerLogFiles(None).tail(PREFIXED, 5), [])

    def test_huge_file_is_read_only_from_the_end(self):
        src = DockerLogFiles(self.base, max_bytes=2000)
        write_log(self.dir, CID + "-json.log",
                  [("t%d" % i, "stdout", "X" * 200) for i in range(200)])
        got = src.tail(PREFIXED, 5)
        self.assertTrue(0 < len(got) <= 5)
        self.assertEqual(got[-1]["message"], "X" * 200)


if __name__ == "__main__":
    unittest.main()

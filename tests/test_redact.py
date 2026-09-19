import unittest

from tests import fakes  # noqa: F401  (setzt sys.path)
from redact import MASK, redact


class RedactTest(unittest.TestCase):
    def check(self, line, secret):
        out = redact(line)
        self.assertNotIn(secret, out, out)
        self.assertIn(MASK, out)

    def test_key_value_forms(self):
        self.check("login password=hunter2 ok", "hunter2")
        self.check('{"api_key": "abc123def"}', "abc123def")
        self.check("DB_PASS: s3cr3t!", "s3cr3t!")
        self.check("MYSQL_ROOT_PASSWORD='geheim wort'", "geheim wort")

    def test_headers_and_tokens(self):
        self.check("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop")
        self.check("Set-Cookie: session=xyz; HttpOnly", "xyz")
        self.check("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlMTIz", "c2lnbmF0dXJlMTIz")
        self.check("GET /api?foo=1&token=zzz999 200", "zzz999")
        self.check("connect postgres://app:pw1234@db:5432/x", "pw1234")
        self.check("key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "0123456789abcdef")

    def test_harmless_lines_untouched(self):
        line = "[INF] Jellyfin started on port 8096 in 1234 ms"
        self.assertEqual(redact(line), line)


if __name__ == "__main__":
    unittest.main()

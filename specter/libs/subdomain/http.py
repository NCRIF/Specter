# this file contains all the http helpers


import urllib.error
import urllib.request
from html.parser import HTMLParser

from .constants import HTTP_TO, SSL_CTX, UA


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in = False

    def handle_data(self, data):
        if self._in:
            self.title += data


def http_get(
    url,
    timeout = HTTP_TO,
    max_bytes = 5 << 20,
):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            body = resp.read(max_bytes) if max_bytes > 0 else resp.read()
            return resp.status, body, dict(resp.headers), ""
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(65536), dict(exc.headers), str(exc)
        except Exception:
            return exc.code, b"", {}, str(exc)
    except Exception as exc:
        return 0, b"", {}, str(exc)


import os
from xml.etree.ElementTree import parse
import re
import sys

os.chdir(r'.')
files = os.listdir('.')
target = ""
domre = re.compile('')

if len(sys.argv) == 2:
    tree = parse(sys.argv[1])
else:
    sys.exit(0)

class HeaderDict(object):

    def __init__(self, allow_multiple=False):
        self._storage = {}
        self.allow_multiple = allow_multiple

    def __getitem__(self, name):
        name = name.lower()
        return self._storage.get(name)

    def __setitem__(self, name, value):
        name = name.lower()
        if self.allow_multiple and name in self._storage:
            tmp = self._storage.get(name)
            if isinstance(tmp, list):
                self._storage[name].append(value)
            else:
                self._storage[name] = [tmp, value]
        else:
            self._storage[name] = value
        return None

    def __contains__(self, key):
        key = key.lower()
        return key in self._storage

    def get(self, key, value=None):
        key = key.lower()
        if key in self._storage:
            return self._storage[key]
        return value

    def keys(self):
        return self._storage.keys()

for item in tree.iterfind('./item'):
    url, response = "", ""
    for c in item.getchildren():
        if c.tag == "url":
            url = c.text
        elif c.tag == "response":
            try:
                response = c.text.decode('base64')
            except:
                response = c.text

    if domre.search(url) is None:
        continue

    if response is None:
        continue

    tmp = response.split('\r\n\r\n')
    tmp = tmp[0].split('\r\n')

    headers = HeaderDict()

    for t in tmp:
        if ':' in t:
            k,v = t.split(': ', 1)
            headers[k] = v

    if "x-frame-options" not in headers:
        print "{0}".format(url)

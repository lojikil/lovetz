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

    print "Header report for {0}".format(url)

    if "cache-control" in headers:
        if "must-revalidate" not in headers["cache-control"]:
            print "URL returns a weak 'cache-control' value: {0}".format(headers["cache-control"])
    else:
        print "Cache-control header not found!"

    if "pragma" in headers:
        if headers["pragma"] != "no-cache":
            print "Site defines a pragma header with value {0}".format(headers["pragma"])
    else:
        print "Pragma header not found!"

    if "x-xss-protection" in headers:
        if headers["x-xss-protection"] != "1; mode=block":
            print "Weak 'x-xss-protection' header defined!"
    else:
        print "No X-XSS-Protection header defined!"

    if "x-content-type-options" in headers:
        if headers['x-content-type-options'] != 'nosniff':
            print "Site returns weak 'x-content-type-options' value: {0}".format(headers['x-content-type-options'])
    else:
        print "x-content-type-options not found!"

    if "expires" in headers:
        print "Expires value: {0}".format(headers['expires'])
    else:
        print "Expires header not defined!"

    if "x-frame-options" in headers:
        print "x-frame-options value: {0}".format(headers['x-frame-options'])
    else:
        print "x-frame-options header not defined!"

    if "set-cookie" in headers:
        tmp = headers['set-cookie']
        if isinstance(tmp, list):
            misc, miss = False, False
            for cookie in tmp:

                if 'httponly' not in cookie:
                    misc = True
                if 'secure' not in cookie:
                    miss = True

                if not misc and not miss:
                    print "Cookies contain all necessary headers"
                else:
                    print "Cookie missing: "
                    if misc:
                        print "httponly ",
                    if miss:
                        print "secure ",

                    print ""
        else:
            tmp = tmp.lower()
            if 'httponly' not in tmp:
                print "cookie missing httponly: {0}".format(headers['set-cookie'])

            if 'secure' not in tmp:
                print "cookie missing secure: {0}".format(headers['set-cookie'])
    else:
        pass

    if "x-powered-by" in headers:
        print "x-powered-by value found! {0}".format(headers['x-powered-by'])

    if "server" in headers:
        print "server value found: {0}".format(headers['server'])

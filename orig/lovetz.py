import os
from xml.etree.ElementTree import parse
import json
import re
import argparse
import sys
import getopt


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


class LovetzPlugin(object):

    def __init__(self, dom=None):

        if dom not is None:
            self.domre = re.compile(dom)
        else:
            self.domre = None
        self.secre = re.compile('[Ss][Ee][Cc][Uu][Rr][Ee];?')
        self.htore = re.compile('[Hh][Tt]{2}[Pp][Oo][Nn][Ll][Yy];?')
        pass

    def check(self, url, response_headers, request_headers,
              response, request):
        raise NotImplemented("base lovetz plugin class")

    def log(self, event, url, message, request_heders=None,
            response_headers=None, response=None, request=None):
        pass


class CORSPlugin(LovetzPlugin):

    def check(self, url, response_headers, request_headers,
              response, request):
        if 'access-control-allow-origin' in response_headers:
            print "Header report for {0}".format(url)


class LovetzCookie(object):
    """ Simple HTTP Cookie parser.

    """
    __slots__ = ['httponly', 'secure', 'comment', 'path', 'name',
                 'value', 'expires', 'other', 'domain', 'version']

    def __init__(self, name, value, httponly=False, secure=False,
                 comment=None, path=None, expires=None, domain=None, **other):
        self.name = name
        self.value = value
        self.httponly = httponly
        self.domain = domain
        self.secure = secure
        self.comment = comment
        self.path = path
        self.expires = expires
        self.other = other

    @staticmethod
    def parse_response(val):

        if val[0:11].lower() == "set-cookie:":
            val = val[11:]
        elif val[0:12].lower() == "set-cookie2:":
            val = val[12:]

        vals = val.split(";")
        n, v = vals[0].strip().split("=")
        vals = vals[1:]
        h = {
            'name': n,
            'value': v
        }
        for v in vals:
            parts = v.strip().split("=")

            if len(parts) == 1:
                if parts[0].lower() == "httponly":
                    h['httponly'] = True
                elif parts[0].lower() == "secure":
                    h['secure'] = True
                else:
                    h[parts[0]] = True
            else:
                h[parts[0]] = parts[1]

        return LovetzCookie(**h)

    @staticmethod
    def parse_request(val):

        if val[0:7].lower() == "cookie:":
            val = val[7:]

        vals = val.split(";")
        cookies = []

        for v in vals:
            k, cv = v.split("=")
            cookies.append(LovetzCookie(name=k, value=cv))

        return cookies


class CookiePlugin(LovetzPlugin):

    def check(self, url, response_headers, request_headers,
              response, request):

        # I wonder if we should check other things, like comment
        # vesion, expires, path...

        cookies_httponly = []  # missing httponly
        cookies_secure = []    # missing secure
        cookies_both = []     # missing both
        cookies_fine = []     # having all flags

        if "set-cookie" in response_headers:
            tmp = response_headers['set-cookie']
            if isinstance(tmp, list):

                for cookie in tmp:

                    c = LovetzCookie.parse_response(cookie)

                    if not c.httponly and not c.secure:
                        cookies_both.append(cookie)
                    elif not c.httponly:
                        cookies_httponly.append(cookie)
                    elif not c.secure:
                        cookies_secure.append(cookie)
                    else:
                        cookies_fine.append(cookie)
            else:
                c = LovetzCookie.parse_response(tmp)
                if not c.httponly and not c.secure:
                    cookies_both.append(tmp)
                elif not c.httponly:
                    cookies_httponly.append(tmp)
                elif not c.secure:
                    cookies_secure.append(tmp)
                else:
                    cookies_fine.append(tmp)
        else:
            pass

        if cookies_httponly:
            msg = "Cookies missing 'http only': {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([c.name
                                           for c in cookies_httponly])))

        if cookies_secure:
            msg = "Cookies missing 'secure': {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([c.name
                                           for c in cookies_httponly])))

        if cookies_both:
            msg = "Cookies missing both 'secure' and 'http only': {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([c.name
                                           for c in cookies_httponly])))

        if cookies_httponly:
            msg = "Cookies with the correct flags: {0}"
            self.log(LOG_INFO,
                     url,
                     msg.format(', '.join([c.name
                                           for c in cookies_httponly])))


class HeaderPlugin(LovetzPlugin):

    def check(self, url, response_response_headers, request_response_headers,
              response, request):
        print "Header report for {0}".format(url)

        if "cache-control" in response_headers:
            if "must-revalidate" not in response_headers["cache-control"]:
                msg = "Weak 'cache-control' value: {0}"
                self.log(LOG_WARN,
                         url,
                         msg.format(response_headers["cache-control"])
        else:
            self.log(LOG_WARN,
                     url,
                     "Cache-control header not found!")

        if "pragma" in response_headers:
            msg = "Site defines a pragma header with value {0}"
            if response_headers["pragma"] != "no-cache":
                self.log(LOG_WARN,
                         url,
                         msg.format(response_headers["pragma"])
        else:
            self.log(LOG_WARN,
                     url,
                     "Pragma header not found!")

        if "x-xss-protection" in response_headers:
            if response_headers["x-xss-protection"] != "1; mode=block":
                self.log(LOG_WARN,
                         url,
                        "Weak 'x-xss-protection' header defined!")
        else:
            self.log(LOG_WARN,
                     url,
                     "No X-XSS-Protection header defined!")

        if "x-content-type-options" in response_headers:
            msg = "Site returns weak 'x-content-type-options' value: {0}"
            if response_headers['x-content-type-options'] != 'nosniff':
                self.log(LOG_WARN,
                         url,
                         msg.format(response_headers['x-content-type-options'])
        else:
            self.log(LOG_WARN,
                     url,
                     "x-content-type-options not found!")

        if "expires" in response_headers:
            self.log(LOG_WARN,
                     url,
                     "Expires value: {0}".format(response_headers['expires'])
        else:
            self.log(LOG_WARN,
                     url,
                     "Expires header not defined!")

        if "x-frame-options" in response_headers:
            # need to do actual analysis here...
            msg = "x-frame-options value: {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(response_headers['x-frame-options'])
        else:
            self.log(LOG_WARN,
                     url,
                     "x-frame-options header not defined!")

        # could probably do some app finger printing here...

        if "x-powered-by" in response_headers:
            msg = "x-powered-by value found! {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(response_headers['x-powered-by']))

        if "server" in response_headers:
            msg = "server value found: {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(response_headers['server']))


class JSDumpingPlugin(LovetzPlugin):

    # inspired by what https://github.com/sxthomas is doing
    # with his tool

    def check(self, url, response_headers, request_headers,
              response, request):
        pass


if __name__ == "__main__":

    #os.chdir(r'CHANGE TO PATH')
    #files = os.listdir('.')
    target = ""
    #tree = parse('CHANGE TO FILE.xml')

    if sys.argv == 1:
        print "usage: lovetz.py [options] <file>"
        sys.exit(0)

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
                k, v = t.split(': ', 1)
                headers[k] = v

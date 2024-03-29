from xml.etree.ElementTree import parse
import json
import csv
import re
import argparse
import sys
import urlparse
import os.path


LOG_ERROR = 2
LOG_WARN = 1
LOG_INFO = 0

# these are defined this way so that
# they cannot be confused with
# the above. Honestly I should make
# them into a separate type & what not
# but Python isn't really geared for that

LOG_RAW = "raw"
LOG_JSON = "json"
LOG_CSV = "csv"


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

    def __init__(self, style=LOG_RAW, verbose=True):
        # no longer need to have the DOM checks here; moved them to the
        # reader, which I believe is a cleaner location.
        self.events = []
        self.style = style
        self.verbose = verbose

    def check(self, url, response_headers, request_headers,
              response_body, request_body, request_status, response_status):
        raise NotImplemented("base lovetz plugin class")

    def log(self, event, url, message, request_headers=None,
            response_headers=None, response=None, request=None):

        # really, this should be just access a class-level member that
        # handles the actual output... but for now this is enough.

        outputs = ["[-]", "[!]", "[+]"]

        self.events.append(dict(source=self.__class__.__name__,
                                event=event,
                                url=url,
                                message=message,
                                request_headers=request_headers,
                                response_headers=response_headers,
                                request=request,
                                response=response))
        if self.verbose:
            print "{0} ({1}) {2} for {3}".format(outputs[event],
                                               self.__class__.__name__,
                                               message,
                                               url)


class CORSPlugin(LovetzPlugin):

    def check(self, url, response_headers, request_headers,
              response_body, request_body, request_status, response_status):

        headers = ["access-control-allow-methods",
                   "access-control-allow-headers",
                   "access-control-max-age",
                   "access-control-expose-headers",
                   "access-control-allow-credentials"]

        if 'access-control-allow-origin' in response_headers:
            val = response_headers['access-control-allow-origin']

            if val == "*":
                self.log(LOG_WARN,
                         url,
                         "Widely-scoped access-control-allow-origin header")
                if "access-control-allow-credentials" in response_headers:
                    self.log(LOG_WARN,
                             url,
                             "Wildcard ACAO with credentials allowed")
                if ("access-control-expose-headers" in response_headers and \
                    "authorization" in response_headers["access-control-expose-headers"]) or \
                   ("access-control-allow-headers" in response_headers and \
                    "authorization" in response_headers["access-control-allow-headers"]):
                    self.log(LOG_WARN,
                             url,
                             "Wildcard ACAO with authorization allowed")
            else:
                self.log(LOG_INFO,
                         url,
                         "CORS Origin: {0}".format(val))

        for header in headers:
            if header in response_headers:
                val = response_headers[header]
                self.log(LOG_INFO,
                         url,
                         "CORS Header {0} with value {1}".format(header, val))


class LovetzCookie(object):
    """ Simple HTTP Cookie parser.

    """
    __slots__ = ['httponly', 'secure', 'comment', 'path', 'name',
                 'value', 'expires', 'other', 'domain', 'version',
                 'samesite']

    def __init__(self, name, value, httponly=False, secure=False,
                 comment=None, path=None, expires=None, domain=None,
                 samesite=None, **other):
        self.name = name
        self.value = value
        self.httponly = httponly
        self.domain = domain
        self.secure = secure
        self.comment = comment
        self.path = path
        self.expires = expires
        self.other = other
        self.samesite = samesite

    @staticmethod
    def parse_response(val):

        if val[0:11].lower() == "set-cookie:":
            val = val[11:]
        elif val[0:12].lower() == "set-cookie2:":
            val = val[12:]

        vals = val.split(";")
        tmp = vals[0].strip().split("=")
        if len(tmp) == 2:
            n = tmp[0]
            v = tmp[1]
        else:
            n = tmp
            v = ""

        vals = vals[1:]
        h = {
            'name': n,
            'value': v
        }
        for v in vals:
            parts = v.strip().split("=")
            parts[0] = parts[0].lower()

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


class ETagPlugin(LovetzPlugin):

    def check(self, url, response_headers, request_headers,
              response_body, request_body, response_status, request_status):

        if "etag" in response_headers:
            val = response_headers["etag"]
            self.log(LOG_WARN,
                     url,
                     "ETag in response: {0}".format(val))


class CookiePlugin(LovetzPlugin):

    def check(self, url, response_headers, request_headers,
              response_body, request_body, response_status, request_status):

        # I wonder if we should check other things, like comment
        # vesion, expires, path...

        cookies_httponly = []  # missing httponly
        cookies_secure = []    # missing secure
        cookies_both = []     # missing both
        cookies_fine = []     # having all flags
        cookies_samesite_none = []
        cookies_samesite_lax = []
        cookies_missing_samesite = []

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

                    if c.samesite == "None":
                        cookies_samesite_none.append(cookie)
                    elif c.samesite == "lax" or c.samesite == "Lax":
                        cookies_samesite_lax.append(cookie)
                    elif c.samesite == None:
                        cookies_missing_samesite.append(cookie)
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

                if c.samesite == "None":
                    cookies_samesite_none.append(tmp)
                elif c.samesite == "lax" or c.samesite == "Lax":
                    cookies_samesite_lax.append(tmp)
                elif c.samesite == None:
                    cookies_missing_samesite.append(tmp)
        else:
            pass

        if cookies_httponly:
            msg = "Cookies missing 'http only': {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([ct
                                           for ct in cookies_httponly])))

        if cookies_secure:
            msg = "Cookies missing 'secure': {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([cs
                                           for cs in cookies_secure])))

        if cookies_both:
            msg = "Cookies missing both 'secure' and 'http only': {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([cb
                                           for cb in cookies_both])))

        if cookies_samesite_none:
            msg = "Cookies with SameSite explicitly set to None: {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([cb
                                           for cb in cookies_samesite_none])))

        if cookies_samesite_lax:
            msg = "Cookies with SameSite explicitly set to lax: {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([cb
                                           for cb in cookies_samesite_lax])))

        if cookies_missing_samesite:
            msg = "Cookies missing SameSite: {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(', '.join([cb
                                           for cb in cookies_missing_samesite])))

        if cookies_fine:
            msg = "Cookies with the correct flags: {0}"
            self.log(LOG_INFO,
                     url,
                     msg.format(', '.join([cf
                                           for cf in cookies_fine])))


class FingerprintPlugin(LovetzPlugin):
    """ Attempt to fingerprint an application based on:

        - URL: does it contain "wp-", ".do", &c.?
        - Headers: any "X-Powered-By"?
        - bodies: any tell-tale information therein?
    """

    def check(self, url, response_headers, request_headers,
              response_body, request_body, response_status, request_status):

        if not hasattr(self, 'replugins'):
            # compile a big mess of regular expressions that we
            # can use later for checking URLs. The checks themselves
            # are actually a tuple of re-object, location-string
            # The location string has the following values:
            # - both: check the body & the URL
            # - body: check *only* the (response) body
            # - header: check the X-Powered-By header
            # - url: check *only* the URL
            # note that "both" does NOT imply checking the header;
            # maybe we should add an "all" directive?

            self.replugins = {
                'Wordpress': (re.compile('/wp-', re.I), "both"),
                'WordPress powered by': (re.compile('Powered By WordPress',
                                                    re.I), 'body'),
                'phpMyAdmim': (re.compile('/phpMyAdmin', re.I), "both"),
                'php': (re.compile('\.php', re.I), "url"),
                'Struts 1': (re.compile('\.do', re.I), "url"),
                'Struts 2': (re.compile('\.action', re.I), "url"),
                'ASP': (re.compile('\.asp$', re.I), "url"),
                'ASP.Net': (re.compile('\.aspx$', re.I), "url"),
                'ASP.Net Header': (re.compile('ASP\.NET', re.I), "header"),
                'Outlook Web Access': (re.compile('/owa/', re.I), 'url'),
                'Exchange': (re.compile('/exchweb', re.I), 'url'),
                'CGI': (re.compile('/cgi-?(bin)?', re.I), 'url'),
                'ColdFusion': (re.compile('\.(cfm|cfc)', re.I), 'url')
            }

        for fpname, fptuple in self.fingerprints:

            fingerprint, location = fptuple

            if location == "body":
                if fingerprint.search(response_body) is not None:
                    pass
                    # self.log(LOG_WARN, url, msg.format(fpname))
            elif location == "header":
                pass
            elif location == "url":
                pass
            elif location == "both":
                pass


class IDsInURLPlugin(LovetzPlugin):
    """ Attempt to uncover sensitive data such as session IDs in URLs.
    """

    def check(self, url, response_headers, request_headers,
              response_body, request_body, response_status, request_status):
        pass


class AutocompletePlugin(LovetzPlugin):
    """ Autocomplete in HTML warning.
    """

    def check(self, url, response_headers, request_headers,
              response_body, request_body, response_status, request_status):
        pass


class HeaderPlugin(LovetzPlugin):

    def check(self, url, response_headers, request_headers,
              response_body, request_body, response_status, request_status):

        security_headers = ["cache-control", "pragma", "x-xss-protection",
                            "x-content-type-options", "expires", "x-frame-options",
                            "strict-transport-security", "x-powered-by", "server",
                            "www-authenticate", "content-security-policy",
                            "content-security-policy-report-only"]

        msg = "Response header {0} with value {1}"
        for header in response_headers.keys():
            if header not in security_headers:
                self.log(LOG_INFO,
                         url,
                         msg.format(header, response_headers[header]))

        if not hasattr(self, "server_re"):
            self.server_re = re.compile('[0-9]')

        if "content-security-policy" in response_headers:
            self.log(LOG_INFO,
                     url,
                     "CSP with policy: {0}".format(response_headers["content-security-policy"]))
        else:
            self.log(LOG_WARN,
                     url,
                     "No CSP defined")

        if "content-security-policy-report-only" in response_headers:
            self.log(LOG_INFO,
                     url,
                     "CSP-RO with policy: {0}".format(response_headers["content-security-policy-report-only"]))
        else:
            self.log(LOG_INFO,
                     url,
                     "No CSP-RO defined")

        if "www-authenticate" in response_headers:
            if "Basic realm" in response_headers["www-authenticate"]:
                self.log(LOG_WARN,
                         url,
                         "(www-auth) URL supports Basic authentication: {0}".format(response_headers["www-authenticate"]))
            else:
                self.log(LOG_INFO,
                         url,
                         "(www-auth) URL Authentication: {0}".format(response_headers["www-authenticate"]))

        if "cache-control" in response_headers:
            if "private" in response_headers["cache-control"]:
                self.log(LOG_WARN,
                         url,
                         "Broken cache control: {0}".format(response_headers["cache-control"]))

            if "must-revalidate" not in response_headers["cache-control"]:
                msg = "Weak 'cache-control' value: {0}"
                self.log(LOG_WARN,
                         url,
                         msg.format(response_headers["cache-control"]))
            else:
                self.log(LOG_INFO,
                         url,
                         "Cache-control header found: {0}".format(response_headers["cache-control"]))
        else:
            self.log(LOG_WARN,
                     url,
                     "Cache-control header not found")

        if "pragma" in response_headers:
            msg = "Site defines a pragma header with value {0}"
            if response_headers["pragma"] != "no-cache":
                self.log(LOG_WARN,
                         url,
                         msg.format(response_headers["pragma"]))
        else:
            self.log(LOG_WARN,
                     url,
                     "Pragma header not found")

        if "x-xss-protection" in response_headers:
            if response_headers["x-xss-protection"] != "1; mode=block":
                self.log(LOG_WARN,
                         url,
                         "Weak 'x-xss-protection' header defined")
        else:
            self.log(LOG_WARN,
                     url,
                     "No X-XSS-Protection header defined")

        if "x-content-type-options" in response_headers:
            msg = "Site returns weak 'x-content-type-options' value: {0}"
            pos_msg = "Site returns relatively strong 'x-content-type-options'"
            val = response_headers['x-content-type-options']
            if response_headers['x-content-type-options'] != 'nosniff':
                self.log(LOG_WARN,
                         url,
                         msg.format(val))
            else:
                self.log(LOG_INFO,
                         url,
                         pos_msg)
        else:
            self.log(LOG_WARN,
                     url,
                     "x-content-type-options not found")

        if "expires" in response_headers:
            self.log(LOG_INFO,
                     url,
                     "Expires value: {0}".format(response_headers['expires']))
        else:
            self.log(LOG_WARN,
                     url,
                     "Expires header not defined")

        if "x-frame-options" in response_headers:
            # need to do actual analysis here...
            msg = "non-standard x-frame-options value: {0}"
            dmsg = "site denies framing"
            smsg = "site allows framing from same origin"
            amsg = "site allows framing from: {0}"
            val = response_headers['x-frame-options']

            if val.lower() == "sameorigin":
                self.log(LOG_INFO,
                         url,
                         smsg)
            elif val.lower() == "deny":
                self.log(LOG_INFO,
                         url,
                         dmsg)
            elif val.lower().startswith("allow"):
                self.log(LOG_INFO,
                         url,
                         amsg.format(val))
            else:
                self.log(LOG_INFO,
                         url,
                         msg.format(val))
        else:
            self.log(LOG_WARN,
                     url,
                     "x-frame-options header not defined")

        if "strict-transport-security" in response_headers:
            self.log(LOG_INFO,
                     url,
                     "HSTS found with value: {0}".format(response_headers["strict-transport-security"]))
        else:
            self.log(LOG_WARN,
                     url,
                     "HSTS missing")

        # could probably do some app finger printing here...

        if "x-powered-by" in response_headers:
            msg = "x-powered-by value found! {0}"
            self.log(LOG_WARN,
                     url,
                     msg.format(response_headers['x-powered-by']))

        if "server" in response_headers:
            val = response_headers["server"]
            imsg = "server value found: \"{0}\""
            wmsg = "server with specific version found: \"{0}\""

            if self.server_re.search(val):
                self.log(LOG_WARN,
                         url,
                         wmsg.format(val))
            else:
                self.log(LOG_INFO,
                         url,
                         imsg.format(val))


class JSDumpingPlugin(LovetzPlugin):

    # inspired by what https://github.com/sxthomas is doing
    # with his tool

    def check(self, url, response_headers, request_headers,
              response_body, request_body, response_status, request_status):
        parsed_url = urlparse.urlsplit(url)
        if parsed_url.path.endswith(".js"):
            fname = urlparse.urlsplit(url).path.split('/')[-1]

            # XXX: this is pretty awful
            # I have to split the response status line here, to check
            # those few times that we actually have a 200, instead of
            # a 304 (which would mean it's a cache hit). There's probably
            # some more intelligent things we can do here, like check the
            # size of the JS on disk vs the size we see in the response,
            # but having a parsed status line is key.

            vals = response_status.split(" ")

            if vals[1] == "200" and not os.path.isfile(fname):
                self.log(LOG_INFO,
                         url,
                         "Dumped JavaScript body")
                with open(fname, 'w') as fh:
                    fh.write(response_body)


class LovetzHistoryItem(object):

    # perhaps History items should have a cookie jar attached? That way plugins
    # that wants to operate on cookies needn't do the creation themselves, but
    # rather there would already be a cookie jar attached here... creates a bit
    # more work for the history readers, but shouldn't be terribly difficult...

    __slots__ = ['url', 'request_status', 'request_headers', 'request_body',
                 'response_status', 'response_headers', 'response_body',
                 'myslots']

    def __init__(self, url, req_status, req_headers, req_body,
                 res_status, res_headers, res_body):
        self.url = url
        self.request_status = req_status
        self.request_headers = req_headers
        self.request_body = req_body
        self.response_status = res_status
        self.response_headers = res_headers
        self.response_body = res_body
        self.myslots = ['url', 'request_status', 'request_headers',
                        'request_body', 'response_status', 'response_headers',
                        'response_body']

    def keys(self):
        return self.myslots

    def __getitem__(self, key):
        if key not in self.myslots:
            return KeyError("no such key: {0}".format(key))

        # I could do this by reaching into self.__class__, but...
        # yuck
        if key == "url":
            return self.url
        elif key == "request_status":
            return self.request_status
        elif key == "request_headers":
            return self.request_headers
        elif key == "request_body":
            return self.request_body
        elif key == "response_status":
            return self.response_status
        elif key == "response_headers":
            return self.response_headers
        elif key == "response_body":
            return self.response_body


class LovetzReader(object):

    def __init__(self, filename=None, loadNow=False, dom=None, domre=False):
        self.filename = filename

        if loadNow:
            self.load()

        if dom:
            if not domre:  # the dom param is NOT a regular expression...
                # so we want to make the READER check whether or not we should
                # consume an object, rather than plugin. In this case, the
                # domain is *NOT* a regular expression, so we convert
                # it into one.
                self.dom = re.compile(dom.replace(".",
                                                  "\\.").replace("?",
                                                                 "\\?"),
                                      re.I)
            else:
                self.dom = re.compile(dom, re.I)
        else:
            self.dom = None

    def load(self, filename=None):
        raise NotImplemented("load not implemented in base")

    def loadable(self):
        raise NotImplemented("loadable not implemented in base")

    def iteritem(self):
        raise NotImplemented("iteritem not implemented in base")


class HARReader(LovetzReader):

    def load(self, filename=None):
        if filename is not None:
            self.filename = filename
            self.json_doc = None
            with file(self.filename, 'r') as f:
                self.json_doc = json.load(f)
        else:
            self.filename = None
            self.json_doc = None

    def _headers(self, headers):
        res = HeaderDict()

        if headers is None:
            return res

        for item in headers:
            res[item['name']] = item['value']

        return res

    def _request(self, req):
        url = req['url']
        method = req['method']
        version = req['httpVersion']
        req_stat = "{0} {1} {2}".format(method, url, version)

        if req['bodySize'] <= 0:
            req_body = ''
        else:
            if req['postData']:
                req_body = req['postData']['text']
            else:
                req_body = req['body']

        req_headers = self._headers(req['headers'])

        return (url, req_stat, req_headers, req_body)

    def _response(self, res):
        scode = res['status']
        stext = res['statusText']
        ver = res['httpVersion']

        res_headers = self._headers(res['headers'])

        res_stat = "{0} {1} {2}".format(ver, scode, stext)

        if res['bodySize'] <= 0:
            res_body = ''
        else:
            res_body = res['content']['text']

        return (res_stat, res_headers, res_body)

    def iteritem(self):

        for entry in self.json_doc['log']['entries']:
            req = self._request(entry['request'])
            res = self._response(entry['response'])

            yield LovetzHistoryItem(req[0], req[1], req[2], req[3],
                                    res[0], res[1], res[2])


class BurpProxyReader(LovetzReader):

    def load(self, filename=None):
        if filename is not None:
            self.filename = filename
            self.tree = parse(self.filename)
        else:
            self.tree = None
            self.filename = None

    def _headers(self, item):
        tmp = item.split('\r\n\r\n')
        body = tmp[1]
        tmp = tmp[0].split('\r\n')
        status = tmp[0]
        tmp = tmp[1:]

        headers = HeaderDict()

        for t in tmp:
            if ':' in t:
                k, v = t.split(': ', 1)
                headers[k] = v
        return (status, headers, body)

    def iteritem(self):

        if self.tree is None:
            raise Exception("no file has been previously loaded")

        for item in self.tree.iterfind('./item'):
            url, response, request = "", "", ""
            for c in item.getchildren():
                if c.tag == "url":
                    url = c.text
                elif c.tag == "response":
                    try:
                        response = c.text.decode('base64')
                    except:
                        response = c.text
                elif c.tag == "request":
                    try:
                        request = c.text.decode('base64')
                    except:
                        request = c.text

            if self.dom and self.dom.search(url) is None:
                continue

            # are there actually cases wherein we care about
            # requests that failed... at the network level?
            # debugging?

            if response is None:
                continue

            req_status, req_head, req_body = self._headers(request)
            res_status, res_head, res_body = self._headers(response)

            yield LovetzHistoryItem(url, req_status, req_head, req_body,
                                    res_status, res_head, res_body)


class IEReader(LovetzReader):

    def load(self, filename=None):
        if filename is not None:
            try:
                self.filename = filename
                self.tree = parse(self.filename)
            except:
                self.tree = None
                self.filename = None
        else:
            self.filename = None
            self.tree = None

    def _headers(self, headers_element):

        res = HeaderDict()

        if headers_element is None:
            return res

        for header in headers_element.iterfind("./header"):
            name = header.find("./name").text
            value = header.find("./value").text
            res[name] = value

        return res

    def _request(self, req_element):

        # anaphoric if would be nice here, at least
        # for null checks. Code is kinda yucky, tbqh.

        method = req_element.find("./method").text
        url = req_element.find("./url").text
        ver = req_element.find("./httpVersion").text

        status = "{0} {1} {2}".format(method, url, ver)

        headers = self._headers(req_element.find("./headers"))

        body_size = req_element.find("./bodySize").text

        body_content = None

        if int(body_size) != 0:
            body_content = req_element.find("./content/text").text
        else:
            body_content = ""

        return (url, status, headers, body_content)

    def _response(self, res_element):

        numstat = res_element.find("./status").text
        message = res_element.find("./statusText").text
        ver = res_element.find("./httpVersion").text

        status = "{0} {1} {2}".format(numstat, message, ver)

        headers = self._headers(res_element.find("./headers"))

        body_size = res_element.find("./bodySize").text

        body_content = None

        if int(body_size) != 0:
            body = res_element.find("./content/text")

            if body is not None:
                body_content = res_element.find("./content/text").text
            else:
                # this must mean there's some other type of node...
                # TODO: check this out
                # NOTE: ah, seems to be regarding Binary content... look into
                # this further
                body_content = ""
        else:
            body_content = ""

        return (status, headers, body_content)

    def iteritem(self):

        if self.tree is None:
            raise Exception("no file has been previously loaded")

        for item in self.tree.iterfind("./entries/entry"):
            req = self._request(item.find("./request"))
            res = self._response(item.find("./response"))

            # named tuple might be nicer here, just for legibility...
            yield LovetzHistoryItem(req[0], req[1], req[2], req[3],
                                    res[0], res[1], res[2])


def dump_logs(events, style=LOG_RAW, location=None):

    fields = ["event", "url", "message", "request_headers",
              "response_headers", "request", "response"]
    outputs = ["[-]", "[!]", "[+]"]

    if style is LOG_RAW:

        for event in events:
            line = "{0} {1} for {2}".format(outputs[event.event],
                                            event.message,
                                            event.url)
            if location is None:
                print line
            else:
                location.write(line + "\n")
    elif style is LOG_CSV:
        writer = csv.DictWriter(location, fieldnames=fields)
        for event in events:
            writer.writerow(event)
    elif style is LOG_JSON:
        output = json.dumps({'events': events})
        if location is None:
            print output
        else:
            location.write(output)


if __name__ == "__main__":

    if sys.argv < 4:
        print "usage: lovetz.py [options] <file>"
        sys.exit(0)

    desc = """ Lovetz: a passive history scanner.
Lovetz is meant to mimic tools such as ZAP and Burp, but in an off-line
passive way; Instead of scanning browsing data whilst actively browsing,
Lovetz scans browsing data after-the-fact, from data generated by
browsers themselves. As such, it has readers for multiple sources
including Burp's history file format, and InternetExplorer's NetworkData."""

    argp = argparse.ArgumentParser(description=desc)

    argp.add_argument('-T',
                      dest='filetype',
                      help="the type of history file to load (burp|ie|har)",
                      type=str)
    argp.add_argument('-F',
                      dest='filename',
                      help="the name of the history file",
                      type=str)
    argp.add_argument('-o',
                      dest='outputtype',
                      help="the type of output (text|csv|json)",
                      type=str)
    argp.add_argument('-O',
                      dest='outputlocation',
                      help="the output file location, if any",
                      type=str)
    argp.add_argument('-J',
                      dest='jsdumping',
                      default=False,
                      const=True,
                      action="store_const",
                      help="enable dumping JavaScript files from history")

    args = argp.parse_args()

    reader = None

    if args.filetype == "burp":
        reader = BurpProxyReader()
    elif args.filetype == "ie":
        reader = IEReader()
    elif args.filetype == "har":
        reader = HARReader()
    else:
        print "filetype must be one of: burp, ie, har"
        sys.exit(1)

    if args.filename == "":
        print "filename must be specified"
        sys.exit(2)

    reader.load(args.filename)
    plugins = [CORSPlugin(),
               CookiePlugin(),
               HeaderPlugin(),
               ETagPlugin()]

    if args.jsdumping:
        print "[!] adding JS File Dumping"
        plugins.append(JSDumpingPlugin())

    for item in reader.iteritem():
        for plugin in plugins:
            plugin.check(**item)

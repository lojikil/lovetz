import os
from xml.etree.ElementTree import parse
import re
import sys

if len(sys.argv) == 2:
    tree = parse(sys.argv[1])
else:
    sys.exit(0)


target = ""
domre = re.compile('HOST')
secre = re.compile('[Ss][Ee][Cc][Uu][Rr][Ee];?')
htore = re.compile('[Hh][Tt]{2}[Pp]-[Oo][Nn][Ll][Yy];?')

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

htcookies = set()
sccookies = set()

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

	headers = HeaderDict(allow_multiple=True)

	for t in tmp:
		if ':' in t:
			k,v = t.split(': ', 1)
			headers[k] = v

	if 'set-cookie' in headers:
		v = headers['set-cookie']
		if isinstance(v, list):
			for value in v:
				if secre.search(value) is None:
					sccookies.add(value)
				if htore.search(value) is None:
					htcookies.add(value)
		else:
			if secre.search(v) is None:
				sccookies.add(v)
			if htore.search(v) is None:
				htcookies.add(v)

for cookie in sccookies:
	print "Cookie missing 'secure' flag: {0}".format(cookie)

for cookie in htcookies:
	print "Cookie missing 'http-only' flag: {0}".format(cookie)

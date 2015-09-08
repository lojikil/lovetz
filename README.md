# Overview:

Passive History Scanner written in Python, that performs checks similar to the passive scanners in Burp or ZAP. However, instead of working in 
line with current testing, it is meant to work with history files from browsers, such as Chrome's HAR files, or XML from IE.

## Rationale

 Very often whilst testing, clients will put us on machines with restricted toolsets; maybe we can only use Burp free, or perhaps
even only browsers. However, we still want to be able to get those "coverage" items, such as Cache control headers, out of our
assessments. Lovetz is meant to help with this, by allowing testers & analysts to save history files from multiple sources, and
run a standard set of plugins across those sources. It can even be used to process disperate sources: perhaps the external portion
could use Burp, but the internal portion required Internet Explorer. 

So, explicit goals are:

- multiple sources of "readers" should be supported.
- many types of plugins should be easily written.
- support for out-of-band discovery of resources.
- leveraging other tools (such as SAST for JavaScript).
- normalization of results across tool sets.

explicit non-goals are:

- any form of active penetration testing: this should be handled by other tools.
- storage of results: Lovetz can be used to read in results, but should not be a repository unto itself.

## Name

«ловец» means "hunter" in Bulgarian

iocextract
==========

![Developed by InQuest](https://inquest.net/images/inquest-badge.svg)
![Build Status](https://github.com/InQuest/iocextract/workflows/iocextract-build/badge.svg)
[![Documentation Status](https://readthedocs.org/projects/iocextract/badge/?version=latest)](https://inquest.readthedocs.io/projects/iocextract/en/latest/?badge=latest)
![PyPI Version](https://img.shields.io/pypi/v/iocextract.svg)

[**Indicator of Compromise**](https://en.wikipedia.org/wiki/Indicator_of_compromise) (IOC) extractor for some of the most commonly ingested artifacts.

Table of contents
=================

* [Overview](#overview)
    * [The Problem](#the-problem)
    * [Our Solution](#our-solution)
    * [Example Use Case](#example-use-case)
* [Installation](#installation)
* [Usage](#usage)
    * [Library](#library)
    * [Command Line Interface](#command-line-interface)
* [Helpful Information](#helpful-information)
    * [FAQ](#faq)
    * [More Details](#more-details)
    * [Custom Regex](#custom-regex)
    * [Related Projects](#related-projects)
    * [Contributing](#contributing)

Overview
========

The `iocextract` package is a library and command line interface (CLI) for extracting URLs, IP addresses, MD5/SHA hashes, email addresses, and YARA rules from text corpora. It allows for you to extract encoded and "defanged" IOCs and optionally decode or refang them.

The Problem
-----------

It is common practice for malware analysts or endpoint software to "defang" IOCs such as URLs and IP addresses, in order to prevent accidental exposure to live malicious content. Being able to extract and aggregate these IOCs is often valuable for analysts. Unfortunately, existing "IOC extraction" tools often pass right by them, as they are not caught by standard regex.

For example, the simple defanging technique of surrounding periods with brackets:
```
127[.]0[.]0[.]1
```

Existing tools that use a simple IP address regex will ignore this IOC entirely.

Our Solution
------------

By combining specially crafted regex with some custom post-processing, we are able to both detect and deobfuscate "defanged" IOCs. This saves time and effort for the analyst, who might otherwise have to manually find and convert IOCs into machine-readable format.

Example Use Case
-----------------

Many Twitter users post C2s or other valuable IOC information with defanged URLs.
For example, [this tweet from @InQuest](https://twitter.com/InQuest/status/969469856931287041):

```
Recommended reading and great work from @unit42_intel:
https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/ ...
InQuest customers have had detection for threats delivered from hotfixmsupload[.]com
since 6/3/2017 and cdnverify[.]net since 2/1/18.
```

If we run this through the extractor, we can easily pull out the URLs:

```
https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/
hotfixmsupload[.]com
cdnverify[.]net
```

Passing in `refang=True` at extraction time would remove the obfuscation, but since these are real IOCs, let's leave them defanged in our documentation.

Installation
============

You may need to install the Python development headers in order to install the `regex` dependency. On Ubuntu/Debian-based systems, try:

```bash
sudo apt-get install python-dev
```

Then install `iocextract` from pip:

```bash
pip install iocextract
```

If you have problems installing on Windows, try installing `regex` directly by downloading the [appropriate wheel from PyPI](https://pypi.org/project/regex/#files) and installing via `pip`:

```bash
pip install regex-2018.06.21-cp27-none-win_amd64.whl
```

Usage
=====

Library
-------

Try extracting some defanged URLs:

```python
import iocextract

content = \
"""
I really love example[.]com!
All the bots are on hxxp://example.com/bad/url these days.
C2: tcp://example[.]com:8989/bad
"""

for url in iocextract.extract_urls(content):
    print(url)

    # Output

    # hxxp://example.com/bad/url
    # tcp://example[.]com:8989/bad
    # example[.]com
    # tcp://example[.]com:8989/bad
```

NOTE: Some URLs may show up twice if they are caught by multiple regexes.

If you want, you can also "refang", or remove common obfuscation methods from IOCs:

```python
import iocextract

for url in iocextract.extract_urls(content, refang=True):
    print(url)

    # Output

    # http://example.com/bad/url
    # http://example.com:8989/bad
    # http://example.com
    # http://example.com:8989/bad
```

If you don't want to defang the extracted IOCs at all during extraction, you can disable this as well:

```python
import iocextract

content = \
"""
http://example.com/bad/url
http://example.com:8989/bad
http://example.com
http://example.com:8989/bad
"""

for url in iocextract.extract_urls(content, defang=False):
    print(url)

    # Output

    # http://example.com/bad/url
    # http://example.com:8989/bad
    # http://example.com
    # http://example.com:8989/bad
```

All `extract_*` functions in this library return iterators, not lists. The benefit of this behavior is that `iocextract` can process extremely large inputs, with a very low overhead. However, if for some reason you need to iterate over the IOCs more than once, you will have to save the results as a list:

```python
import iocextract

content = \
"""
I really love example[.]com!
All the bots are on hxxp://example.com/bad/url these days.
C2: tcp://example[.]com:8989/bad
"""

print(list(iocextract.extract_urls(content)))
# ['hxxp://example.com/bad/url', 'tcp://example[.]com:8989/bad', 'example[.]com', 'tcp://example[.]com:8989/bad']
```

Command Line Interface
----------------------

A command-line tool is also included:

```bash
$ iocextract -h
    usage: iocextract [-h] [--input INPUT] [--output OUTPUT] [--extract-emails]
                  [--extract-ips] [--extract-ipv4s] [--extract-ipv6s]
                  [--extract-urls] [--extract-yara-rules] [--extract-hashes]
                  [--custom-regex REGEX_FILE] [--refang] [--strip-urls]
                  [--wide]

    Advanced Indicator of Compromise (IOC) extractor. If no arguments are
    specified, the default behavior is to extract all IOCs.

    optional arguments:
      -h, --help            show this help message and exit
      --input INPUT         default: stdin
      --output OUTPUT       default: stdout
      --extract-emails
      --extract-ips
      --extract-ipv4s
      --extract-ipv6s
      --extract-urls
      --extract-yara-rules
      --extract-hashes
      --custom-regex REGEX_FILE file with custom regex strings, one per line, with one capture group each
      --refang              default: no
      --strip-urls          remove possible garbage from the end of urls. default: no
      --wide                preprocess input to allow wide-encoded character matches. default: no
```

NOTE: Only URLs, emails, and IPv4 addresses can be "refanged".

Helpful Information
===================

FAQ
---

Are you...

> Q. Extracting possibly-defanged IOCs from plain text, like the contents of tweets or blog posts?
>> A. Yes! This is exactly what iocextract was designed for, and where it performs best. Want to go a step farther and automate extraction and storage? Check out [ThreatIngestor](https://github.com/InQuest/ThreatIngestor).

> Q. Extracting URLs that have been hex or base64 encoded?
>> A. Yes, but the CLI might not give you the best results. Try writing a Python script and calling `iocextract.extract_encoded_urls` directly.

Note: You will most likely end up with extra garbage at the end of URLs.

> Q. Extracting IOCs that have not been defanged, from HTML/XML/RTF?
>> A. Maybe, but you should consider using the `--strip-urls` CLI flag (or the `strip=True` parameter in the library), and you may still get some extra garbage in your output. If you're extracting from HTML, consider using something like [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) to first isolate the text content, and then pass that to iocextract, [like this](https://gist.github.com/rshipp/d399491305c5d293357a800d5a51b0aa).

> Q. Extracting IOCs that have not been defanged, from binary data like executables, or very large inputs?
>> A. There is a very simplistic version of this available when running as a library, but it requires the `defang=False` parameter and could potentially miss some of the IOCs. The regex in iocextract is designed to be flexible to catch defanged IOCs. If you're unable to collect the information you need, consider using something like [Cacador](https://github.com/sroberts/cacador) instead.

More Details
------------

This library currently supports the following IOCs:

* IP Addresses
    * IPv4 fully supported
    * IPv6 partially supported
* URLs
    * With protocol specifier: http, https, tcp, udp, ftp, sftp, ftps
    * With `[.]` anchor, even with no protocol specifier
    * IPv4 and IPv6 (RFC2732) URLs are supported
    * Hex-encoded URLs with protocol specifier: http, https, ftp
    * URL-encoded URLs with protocol specifier: http, https, ftp, ftps, sftp
    * Base64-encoded URLs with protocol specifier: http, https, ftp
* Emails
    * Partially supported, anchoring on `@` or `at`
* YARA rules
    * With imports, includes, and comments
* Hashes
    * MD5
    * SHA1
    * SHA256
    * SHA512
* Telephone numbers
* Custom regex
    * With exactly one capture group

For IPv4 addresses, the following defang techniques are supported:

| Technique       | Defanged      | Refanged  |
|-----------------|---------------|-----------|
| `.` -> `[.]`    | 1[.]1[.]1[.]1 | 1.1.1.1   |
| `.` -> `(.)`    | 1(.)1(.)1(.)1 | 1.1.1.1   |
| `.` -> `\.`     | 1\\.1\\.1\\.1  | 1.1.1.1  |
| Partial         | 1[.1[.1.]1    | 1.1.1.1   |
| Any combination | 1\.)1[.1.)1   | 1.1.1.1   |

For email addresses, the following defang techniques are supported:

| Technique       | Defanged           | Refanged       |
|-----------------|--------------------|----------------|
| `.` -> `[.]`    | me@example[.]com   | me@example.com |
| `.` -> `(.)`    | me@example(.)com   | me@example.com |
| `.` -> `{.}`    | me@example{.}com   | me@example.com |
| `.` -> `_dot_`  | me@example dot com | me@example.com |
| `@` -> `[@]`    | me[@]example.com   | me@example.com |
| `@` -> `(@)`    | me(@)example.com   | me@example.com |
| `@` -> `{@}`    | me{@}example.com   | me@example.com |
| `@` -> `_at_`   | me at example.com  | me@example.com |
| Partial         | me@} example[.com  | me@example.com |
| Added spaces    | me@example [.] com | me@example.com |
| Any combination | me @example [.)com | me@example.com |

For URLs, the following defang techniques are supported:

| Technique       | Defanged                                           | Refanged                  |
|-----------------|----------------------------------------------------|---------------------------|
| `.` -> `[.]`    | `example[.]com/path`                               | `http://example.com/path` |
| `.` -> `(.)`    | `example(.)com/path`                               | `http://example.com/path` |
| `.` -> `\.`     | `example\.com/path`                                | `http://example.com/path` |
| Partial         | `http://example[.com/path`                         | `http://example.com/path` |
| `/` -> `[/]`    | `http://example.com[/]path`                        | `http://example.com/path` |
| [Cisco ESA](https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118775-technote-esa-00.html)   | `http:// example .com /path`                       | `http://example.com/path` |
| `://` -> `__`   | `http__example.com/path`                           | `http://example.com/path` |
| `://` -> `:\\`  | `http:\\example.com/path`                          | `http://example.com/path` |
| `:` -> `[:]`    | `http[:]//example.com/path`                        | `http://example.com/path` |
| `hxxp`          | `hxxp://example.com/path`                          | `http://example.com/path` |
| Any combination | `hxxp__ example( .com[/]path`                      | `http://example.com/path` |
| Hex encoded     | `687474703a2f2f6578616d706c652e636f6d2f70617468`   | `http://example.com/path` |
| URL encoded     | `http%3A%2F%2fexample%2Ecom%2Fpath`                | `http://example.com/path` |
| Base64 encoded  | `aHR0cDovL2V4YW1wbGUuY29tL3BhdGgK`                 | `http://example.com/path` |

NOTE: The tables above are not exhaustive, and other URL/defang patterns may also be extracted correctly. If you notice something missing or not working correctly, feel free to let us know via the [GitHub Issues](https://github.com/inquest/iocextract/issues).

The base64 regex was generated with [@deadpixi](https://github.com/deadpixi)'s [base64 regex tool](https://www.erlang-factory.com/upload/presentations/225/ErlangFactorySFBay2010-RobKing.pdf).

Custom Regex
------------

If you'd like to use the CLI to extract IOCs using your own custom regex, create a plain text file with one regex string per line, and pass it in with the `--custom-regex` flag. Be sure each regex string includes exactly one [capture group](https://www.regular-expressions.info/brackets.html).

For example:

```
http://(example\.com)/
(?:https|ftp)://(example\.com)/
```

This custom regex file will extrac the domain `example.com` from matching URLs. The `(?: )` noncapture group won't be included in matches.

If you would like to extract the entire match, just put parentheses around your entire regex string, like this:

```
(https?://.*?.com)
```

If your regex is invalid, you'll see an error message like this:

```
Error in custom regex: missing ) at position 5
```

If your regex does not include a capture group, you'll see an error message like this:

```
Error in custom regex: no such group
```

Always use a single capture group when working with custom regex. Here's a quick example:

```python
[
    r'(my regex)',  # This yields 'my regex' if the pattern matches
    r'my (re)gex',  # This yields 're' if the pattern matches
]
```

Using more than a single capture group can cause unexpected results. Check out this example:

```python
[
    r'my regex',  # This doesn't yield anything
    r'(my) (re)gex',  # This yields 'my' if the pattern matches
]
```

Why? Because the result will always yield only the first *group* match from each regex.

For more complicated regex queries, you can combine capture and non-capture groups like so:

```python
[
    r'(?:my|your) (re)gex',  # This yields 're' if the pattern matches
]
```

You can now compare the `(?: )` syntax for noncapture groups vs the `( )` syntax for the capture group.


Related Projects
----------------

If iocextract doesn't fit your use case, several similar projects exist. Check out the [defang](https://github.com/topics/defang)  and [indicators-of-compromise](https://github.com/topics/indicators-of-compromise) tags on GitHub, as well as:

* [Cacador](https://github.com/sroberts/cacador) in Go
* [ioc-extractor](https://github.com/ninoseki/ioc-extractor) in JavaScript
* [Cyobstract](https://github.com/cmu-sei/cyobstract) in Python

If you'd like to automate IOC extraction, enrichment, export, and more, check out [ThreatIngestor](https://github.com/InQuest/ThreatIngestor).

If you're working with YARA rules, you may be interested in [plyara](https://github.com/plyara/plyara).

Contributing
------------

If you have a defang technique that doesn't make it through the extractor, or if you find any bugs, Pull Requests and Issues are always welcome. The library is released under a GPL-2.0 [license](https://github.com/InQuest/iocextract/blob/master/LICENSE).

Who's using iocextract?
-----------------------

- [InQuest](https://inquest.net)
- [PacketTotal](https://www.packettotal.com)

Are you using it? Want to see your site listed here? Let us know!
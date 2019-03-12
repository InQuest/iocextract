iocextract
==========

.. image:: https://inquest.net/images/inquest-badge.svg
    :target: https://inquest.net/
    :alt: Developed by InQuest
.. image:: https://travis-ci.org/InQuest/python-iocextract.svg?branch=master
    :target: https://travis-ci.org/InQuest/python-iocextract
    :alt: Build Status
.. image:: https://readthedocs.org/projects/iocextract/badge/?version=latest
    :target: http://inquest.readthedocs.io/projects/iocextract/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://api.codacy.com/project/badge/Grade/920894593bde451c9277c56b7d9ab3e1
    :target: https://app.codacy.com/app/InQuest/python-iocextract
    :alt: Code Health
.. image:: https://api.codacy.com/project/badge/Coverage/920894593bde451c9277c56b7d9ab3e1
    :target: https://app.codacy.com/app/InQuest/python-iocextract
    :alt: Test Coverage
.. image:: http://img.shields.io/pypi/v/iocextract.svg
    :target: https://pypi.python.org/pypi/iocextract
    :alt: PyPi Version

Advanced `Indicator of Compromise`_ (IOC) extractor.

Overview
--------

This library extracts URLs, IP addresses, MD5/SHA hashes, email addresses, and
YARA rules from text corpora. It includes some encoded and "defanged" IOCs in the
output, and optionally decodes/refangs them.

The Problem
-----------

It is common practice for malware analysts or endpoint software to "defang" IOCs
such as URLs and IP addresses, in order to prevent accidental exposure to live
malicious content. Being able to extract and aggregate these IOCs is often valuable
for analysts. Unfortunately, existing "IOC extraction" tools often pass right by them,
as they are not caught by standard regex.

For example, the simple defanging technique of surrounding periods with brackets::

    127[.]0[.]0[.]1

Existing tools that use a simple IP address regex will ignore this IOC entirely.

The Solution
------------

By combining specially crafted regex with some custom postprocessing, we are
able to both detect and deobfuscate "defanged" IOCs. This saves time and effort
for the analyst, who might otherwise have to manually find and convert IOCs into
machine-readable format.

A Simple Use Case
-----------------

Many Twitter users post C2s or other valuable IOC information with defanged URLs.
For example, `this tweet from @InQuest`_::

    Recommended reading and great work from @unit42_intel:
    https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/ ...
    InQuest customers have had detection for threats delivered from hotfixmsupload[.]com
    since 6/3/2017 and cdnverify[.]net since 2/1/18.

If we run this through the extractor, we can easily pull out the URLs::

   https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/
   hotfixmsupload[.]com
   cdnverify[.]net

Passing in ``refang=True`` at extraction time would remove the obfuscation, but
since these are real IOCs, let's leave them defanged in our documentation. :)

Installation
------------

You may need to install the Python development headers in order to install the
``regex`` dependency. On Ubuntu/Debian-based systems, try::

    sudo apt-get install python-dev

Then install ``iocextract`` from pip::

    pip install iocextract

If you have problems installing on Windows, try installing ``regex`` directly
by downloading the `appropriate wheel from PyPI`_ and running e.g.::

    pip install regex-2018.06.21-cp27-none-win_amd64.whl

Usage
-----

Try extracting some defanged URLs::

    >>> content = """
    ... I really love example[.]com!
    ... All the bots are on hxxp://example.com/bad/url these days.
    ... C2: tcp://example[.]com:8989/bad
    ... """
    >>> import iocextract
    >>> for url in iocextract.extract_urls(content):
    ...     print url
    ...
    hxxp://example.com/bad/url
    tcp://example[.]com:8989/bad
    example[.]com
    tcp://example[.]com:8989/bad

Note that some URLs may show up twice if they are caught by multiple regexes.

If you want, you can also "refang", or remove common obfuscation methods from
IOCs::

    >>> for url in iocextract.extract_urls(content, refang=True):
    ...     print url
    ...
    http://example.com/bad/url
    http://example.com:8989/bad
    http://example.com
    http://example.com:8989/bad

You can even extract and decode hex-encoded and base64-encoded URLs::

    >>> content = '612062756e6368206f6620776f72647320687474703a2f2f6578616d706c652e636f6d2f70617468206d6f726520776f726473'
    >>> for url in iocextract.extract_urls(content):
    ...     print url
    ...
    687474703a2f2f6578616d706c652e636f6d2f70617468
    >>> for url in iocextract.extract_urls(content, refang=True):
    ...     print url
    ...
    http://example.com/path

All ``extract_*`` functions in this library return iterators, not lists. The
benefit of this behavior is that ``iocextract`` can process extremely large
inputs, with a very low overhead. However, if for some reason you need to iterate
over the IOCs more than once, you will have to save the results as a list::

    >>> list(iocextract.extract_urls(content))
    ['hxxp://example.com/bad/url', 'tcp://example[.]com:8989/bad', 'example[.]com', 'tcp://example[.]com:8989/bad']

A command-line tool is also included::

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
      --custom-regex REGEX_FILE
                            file with custom regex strings, one per line, with one
                            capture group each
      --refang              default: no
      --strip-urls          remove possible garbage from the end of urls. default:
                            no
      --wide                preprocess input to allow wide-encoded character
                            matches. default: no

Only URLs, emails, and IPv4 addresses can be "refanged".

Should I Use iocextract?
------------------------

Are you...

**Extracting possibly-defanged IOCs from plain text, like the contents of
tweets or blog posts?**

Yes! This is exactly what iocextract was designed for, and where it performs
best. Want to go a step farther and automate extraction and storage? Check out
`ThreatIngestor`_.

**Extracting URLs that have been hex or base64 encoded?**

Yes, but the CLI might not give you the best results. Try writing a Python
script and calling ``iocextract.extract_encoded_urls`` directly.

Note that you will most likely end up with extra garbage at the end of URLs.

**Extracting IOCs that have not been defanged, from HTML/XML/RTF?**

Maybe, but you should consider using the ``--strip-urls`` CLI flag (or the
``strip=True`` parameter in the library), and you may still get some extra
garbage in your output.

If you're extracting from HTML, consider using something like `Beautiful Soup`_
to first isolate the text content, and then pass that to iocextract,
`like this`_.

**Extracting IOCs that have not been defanged, from binary data like
executables, or very large inputs?**

Probably not. The regex in iocextract is designed to be flexible to catch
defanged IOCs, so it performs significantly worse than a solution that is
designed to catch only standard IOCs.

Consider using something like `Cacador`_ instead.

More Details
------------

This library currently supports the following IOCs:

* IP Addresses
    * IPv4 fully supported
    * IPv6 partially supported
* URLs
    * With protocol specifier: http, https, tcp, udp, ftp, sftp, ftps
    * With ``[.]`` anchor, even with no protocol specifier
    * IPv4 and IPv6 (RFC2732) URLs are supported
    * Hex-encoded URLs with protocol specifier: http, https, ftp
    * URL-encoded URLs with protocol specifier: http, https, ftp, ftps, sftp
    * Base64-encoded URLs with protocol specifier: http, https, ftp
* Emails
    * Partially supported, anchoring on ``@`` or ``at``
* YARA rules
    * With imports, includes, and comments
* Hashes
    * MD5
    * SHA1
    * SHA256
    * SHA512
* Custom regex
    * With exactly one capture group

For IPv4 addresses, the following defang techniques are supported:

.. container:: responsive-table

   +-----------------+---------------+-----------+
   | Technique       | Defanged      | Refanged  |
   +=================+===============+===========+
   | ``. -> [.]``    | 1[.]1[.]1[.]1 | 1.1.1.1   |
   +-----------------+---------------+-----------+
   | ``. -> (.)``    | 1(.)1(.)1(.)1 | 1.1.1.1   |
   +-----------------+---------------+-----------+
   | ``. -> \.``     | ``1\.1\.1\.1``| 1.1.1.1   |
   +-----------------+---------------+-----------+
   | Partial         | 1[.1[.1.]1    | 1.1.1.1   |
   +-----------------+---------------+-----------+
   | Any combination | 1\.)1[.1.)1   | 1.1.1.1   |
   +-----------------+---------------+-----------+

For email addresses, the following defang techniques are supported:

.. container:: responsive-table

   +-----------------+--------------------+----------------+
   | Technique       | Defanged           | Refanged       |
   +=================+====================+================+
   | ``. -> [.]``    | me@example[.]com   | me@example.com |
   +-----------------+--------------------+----------------+
   | ``. -> (.)``    | me@example(.)com   | me@example.com |
   +-----------------+--------------------+----------------+
   | ``. -> {.}``    | me@example{.}com   | me@example.com |
   +-----------------+--------------------+----------------+
   | ``. -> _dot_``  | me@example dot com | me@example.com |
   +-----------------+--------------------+----------------+
   | ``@ -> [@]``    | me[@]example.com   | me@example.com |
   +-----------------+--------------------+----------------+
   | ``@ -> (@)``    | me(@)example.com   | me@example.com |
   +-----------------+--------------------+----------------+
   | ``@ -> {@}``    | me{@}example.com   | me@example.com |
   +-----------------+--------------------+----------------+
   | ``@ -> _at_``   | me at example.com  | me@example.com |
   +-----------------+--------------------+----------------+
   | Partial         | me@} example[.com  | me@example.com |
   +-----------------+--------------------+----------------+
   | Added spaces    | me@example [.] com | me@example.com |
   +-----------------+--------------------+----------------+
   | Any combination | me @example [.)com | me@example.com |
   +-----------------+--------------------+----------------+

For URLs, the following defang techniques are supported:

.. container:: responsive-table

   +-----------------+----------------------------------------------------+-----------------------------+
   | Technique       | Defanged                                           | Refanged                    |
   +=================+====================================================+=============================+
   | ``. -> [.]``    | ``example[.]com/path``                             | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | ``. -> (.)``    | ``example(.)com/path``                             | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | ``. -> \.``     | ``example\.com/path``                              | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | Partial         | ``http://example[.com/path``                       | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | ``/ -> [/]``    | ``http://example.com[/]path``                      | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | `Cisco ESA`_    | ``http:// example .com /path``                     | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | ``:// -> __``   | ``http__example.com/path``                         | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | ``:// -> :\\``  | ``http:\\example.com/path``                        | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | ``hxxp``        | ``hxxp://example.com/path``                        | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | Any combination | ``hxxp__ example( .com[/]path``                    | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | Hex encoded     | ``687474703a2f2f6578616d706c652e636f6d2f70617468`` | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | URL encoded     | ``http%3A%2F%2fexample%2Ecom%2Fpath``              | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+
   | Base64 encoded  | ``aHR0cDovL2V4YW1wbGUuY29tL3BhdGgK``               | ``http://example.com/path`` |
   +-----------------+----------------------------------------------------+-----------------------------+

Note that the tables above are not exhaustive, and other URL/defang patterns may
also be extracted correctly. If you notice something missing or not working
correctly, feel free to let us know via the GitHub Issues_.

The base64 regex was generated with `@deadpixi`_'s `base64 regex tool`_.

Custom Regex
------------

If you'd like to use the CLI to extract IOCs using your own custom regex, create
a plain text file with one regex string per line, and pass it in with the
``--custom-regex`` flag. Be sure each regex string includes exactly one
`capture group`_. For example:

.. code-block:: text

    http://(example\.com)/
    (?:https|ftp)://(example\.com)/

This custom regex file will exctract the domain ``example.com`` from matching
URLs. The ``(?: )`` noncapture group won't be included in matches.

If you would like to extract the entire match, just put parentheses around your
entire regex string, like this:

.. code-block:: text

    (https?://.*?.com)

If your regex is invalid, you'll see an error message like this:

.. code-block:: text

    Error in custom regex: missing ) at position 5

If your regex does not include a capture group, you'll see an error message
like this:

.. code-block:: text

    Error in custom regex: no such group

Related Projects
----------------

If iocextract doesn't fit your usecase, several similar projects exist. Check
out the `defang`_  and `indicators-of-compromise`_ tags on GitHub, as well as:

* `Cacador`_ in Go,
* `ioc-extractor`_ in JS, and
* `Cyobstract`_ in Python.

If you'd like to automate IOC extraction, enrichment, export, and more, check
out `ThreatIngestor`_.

If you're working with YARA rules, you may be interested in `plyara`_.

Changelog
---------

New features, improvements, and bugfixes for each release can be found in the
`GitHub releases`_.

Contributing
------------

If you have a defang technique that doesn't make it through the extractor, or
if you find any bugs, PRs and Issues_ are always welcome. The library is
released under a "BSD-New" (aka "BSD 3-Clause") license.

Who's using iocextract
----------------------

* `InQuest <https://inquest.net/>`_
* `PacketTotal <https://www.packettotal.com/>`_

Are you using it? Want to see your site listed here? Let us know!

.. _Indicator of Compromise: https://en.wikipedia.org/wiki/Indicator_of_compromise
.. _Issues: https://github.com/inquest/python-iocextract/issues
.. _this tweet from @InQuest: https://twitter.com/InQuest/status/969469856931287041
.. _Cisco ESA: https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/118775-technote-esa-00.html
.. _GitHub releases: https://github.com/InQuest/python-iocextract/releases
.. _appropriate wheel from PyPI: https://pypi.org/project/regex/#files
.. _@deadpixi: https://github.com/deadpixi
.. _base64 regex tool: http://www.erlang-factory.com/upload/presentations/225/ErlangFactorySFBay2010-RobKing.pdf
.. _capture group: https://www.regular-expressions.info/brackets.html
.. _ThreatIngestor: https://github.com/InQuest/ThreatIngestor
.. _Beautiful Soup: https://www.crummy.com/software/BeautifulSoup/
.. _like this: https://gist.github.com/rshipp/d399491305c5d293357a800d5a51b0aa
.. _Cacador: https://github.com/sroberts/cacador
.. _defang: https://github.com/topics/defang
.. _indicators-of-compromise: https://github.com/topics/indicators-of-compromise
.. _ioc-extractor: https://github.com/ninoseki/ioc-extractor
.. _Cyobstract: https://github.com/cmu-sei/cyobstract
.. _plyara: https://github.com/plyara/plyara
